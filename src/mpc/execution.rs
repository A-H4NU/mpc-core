use itertools::Itertools;
use sha3::{Digest, Sha3_512, digest::generic_array::GenericArray};
use snafu::{self, Snafu};

#[derive(Debug, Snafu)]
pub enum ExecutionContextError {
    #[snafu(display("Invalid configuration: {msg}"))]
    InvalidConfiguration { msg: String },
    #[snafu(display("Execution state error: {op} not allowed in state {state:?}"))]
    StateError { op: String, state: ExecutionState },
    #[snafu(display("Network error: {source}"))]
    NetworkError { source: std::io::Error },
    #[snafu(display("Plan not agreed between parties"))]
    PlanNotAgreed,
    #[snafu(display("Duplicate input for wire {wire}"))]
    DuplicateInput { wire: WireId },
    #[snafu(display("Wire {wire} is not an output of an input operation"))]
    InvalidInputWire { wire: WireId },
    #[snafu(display("Not enough inputs provided"))]
    NotEnoughInputs,
    #[snafu(display("Scheme error during {phase}: {msg}"))]
    SchemeError { phase: String, msg: String },
}

use std::{collections::HashMap, mem::MaybeUninit};

use crate::{
    mpc::{
        NetworkPhaseOutput, Operation,
        circuit::{Round, WireId},
        config::MpcConfig,
        scheme::MpcScheme,
    },
    networking::{Network, ReceiveRequest, RecvLen, SendLen},
};

#[derive(Debug, Clone, Copy)]
pub enum ExecutionState {
    NewBorn,         // just created, no action has been performed
    Handshaked,      // handshaked; checked that parties have the same mpc plan
    FinishedOffline, // finished offline rounds
    ReadyOnline,     // accepted inputs from user
    Finished,        // finished execution
}

type WireMap<S> = HashMap<WireId, <S as MpcScheme>::Wire>;

#[allow(dead_code)]
pub struct ExecutionContext<S, N>
where
    S: MpcScheme,
    N: Network,
{
    config: MpcConfig<S>,
    execution_state: ExecutionState,
    network: N,
    wire_contents: WireMap<S>,
    scheme_context: MaybeUninit<S::Context>,
}

impl<S, N> Drop for ExecutionContext<S, N>
where
    S: MpcScheme,
    N: Network,
{
    fn drop(&mut self) {
        use ExecutionState::*;
        if matches!(
            self.execution_state,
            Handshaked | FinishedOffline | ReadyOnline | Finished
        ) {
            unsafe {
                self.scheme_context.assume_init_drop();
            }
        }
    }
}

macro_rules! assert_state {
    ($fn_name:literal, $state_var:expr, $state_pat:pat) => {
        if !matches!($state_var, $state_pat) {
            return Err(ExecutionContextError::StateError {
                op: $fn_name.to_string(),
                state: $state_var,
            });
        }
    };
}

impl<S, N> ExecutionContext<S, N>
where
    S: MpcScheme,
    N: Network,
{
    pub fn new(config: MpcConfig<S>, network: N) -> Result<Self, ExecutionContextError> {
        if config.n_parties() != network.n_players() {
            return Err(ExecutionContextError::InvalidConfiguration {
                msg: "Mismatch in party ids or counts".to_string(),
            });
        }
        if config.my_id() != network.my_id() {
            return Err(ExecutionContextError::InvalidConfiguration {
                msg: "Mismatch in party ids or counts".to_string(),
            });
        }
        Ok(Self {
            config,
            execution_state: ExecutionState::NewBorn,
            network,
            wire_contents: HashMap::new(),
            scheme_context: MaybeUninit::uninit(),
        })
    }

    pub fn execution_state(&self) -> &ExecutionState {
        &self.execution_state
    }

    pub async fn handshake(&mut self) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        assert_state!("handshake", self.execution_state, ExecutionState::NewBorn);

        let mut hasher = Sha3_512::new();
        hasher.update(&postcard::to_stdvec(&self.config.circuit()).map_err(|e| {
            ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            }
        })?);
        let hash = hasher.finalize();

        let send_len = self.network.broadcast_object(&hash).await.map_err(|e| {
            ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            }
        })?;

        let my_id = self.network.my_id();
        let request: Vec<_> = (0..self.network.n_players())
            .filter(|from| *from != my_id)
            .map(|from| ReceiveRequest::new(from, 1))
            .collect();

        let (hashes, recv_len) = self
            .network
            .recv_objects_many::<GenericArray<_, _>, _>(&request)
            .await
            .map_err(|e| ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            })?;

        if hashes
            .into_iter()
            .any(|x| x.into_iter().next().unwrap() != hash)
        {
            return Err(ExecutionContextError::PlanNotAgreed);
        }

        let context = self
            .config
            .scheme()
            .establish_context(&mut self.network, self.config.circuit())
            .map_err(|e| ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            })?;
        self.scheme_context = MaybeUninit::new(context);

        self.execution_state = ExecutionState::Handshaked;
        Ok((send_len, recv_len))
    }

    fn do_local_operations(
        scheme: &S,
        context: &mut S::Context,
        wire_contents: &mut WireMap<S>,
        round: &Round<S>,
    ) -> Result<(), ExecutionContextError> {
        let ops = round.local_operations();

        for op in ops {
            let inputs = op
                .inputs()
                .map(|id| wire_contents.get(&id).expect("Expected a wire content"))
                .collect::<Vec<_>>();
            let NetworkPhaseOutput {
                pending,
                send_request,
                receive_request,
            } = scheme.do_network_phase(context, op, inputs).map_err(|e| {
                ExecutionContextError::SchemeError {
                    phase: "scheme phase".to_string(),
                    msg: e.to_string(),
                }
            })?;
            assert!(send_request.is_empty());
            assert!(receive_request.is_empty());

            let output = scheme
                .do_finalize_phase(context, pending, Vec::new())
                .map_err(|e| ExecutionContextError::SchemeError {
                    phase: "scheme phase".to_string(),
                    msg: e.to_string(),
                })?;

            for (wire_id, wire_content) in itertools::zip_eq(op.outputs(), output.0) {
                let prev = wire_contents.insert(wire_id, wire_content);
                assert!(prev.is_none());
            }
        }

        Ok(())
    }

    async fn do_network_operations(
        scheme: &S,
        context: &mut S::Context,
        wire_contents: &mut WireMap<S>,
        network: &mut N,
        round: &Round<S>,
    ) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        let ops = round.network_operations();

        let mut pending_ops = Vec::with_capacity(ops.len());
        let mut all_receive_requests = Vec::new();
        let mut all_send_requests = Vec::new();
        let mut receive_request_counts = Vec::with_capacity(ops.len());

        for op in ops {
            let inputs = op
                .inputs()
                .map(|id| wire_contents.get(&id).expect("Expected a wire content"))
                .collect::<Vec<_>>();

            let NetworkPhaseOutput {
                pending,
                mut send_request,
                mut receive_request,
            } = scheme.do_network_phase(context, op, inputs).map_err(|e| {
                ExecutionContextError::SchemeError {
                    phase: "scheme phase".to_string(),
                    msg: e.to_string(),
                }
            })?;

            pending_ops.push(pending);
            receive_request_counts.push(receive_request.len());
            all_send_requests.append(&mut send_request);
            all_receive_requests.append(&mut receive_request);

            assert!(send_request.is_empty());
            assert!(receive_request.is_empty());
        }

        let send_len = network
            .send_objects_many(&all_send_requests)
            .await
            .map_err(|e| ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            })?;

        let (flat_network_data, recv_len) = network
            .recv_objects_many::<S::NetworkElement, _>(&all_receive_requests)
            .await
            .map_err(|e| ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            })?;

        let mut data_iter = flat_network_data.into_iter();

        let mut buffered_results = Vec::with_capacity(ops.len());
        for (op, pending, req_count) in
            itertools::izip!(ops, pending_ops.into_iter(), receive_request_counts)
        {
            let op_data: Vec<_> = data_iter.by_ref().take(req_count).flatten().collect();
            let output = scheme
                .do_finalize_phase(context, pending, op_data)
                .map_err(|e| ExecutionContextError::SchemeError {
                    phase: "scheme phase".to_string(),
                    msg: e.to_string(),
                })?;
            buffered_results.push((op, output));
        }

        for (op, output) in buffered_results {
            for (wire_id, wire_content) in itertools::zip_eq(op.outputs(), output.0) {
                let prev = wire_contents.insert(wire_id, wire_content);
                assert!(prev.is_none());
            }
        }

        Ok((send_len, recv_len))
    }

    pub async fn do_offline(&mut self) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        assert_state!(
            "do_offline",
            self.execution_state,
            ExecutionState::Handshaked
        );

        let mut total_send_len = 0;
        let mut total_recv_len = 0;
        for round in self.config.circuit().offline_rounds().iter() {
            Self::do_local_operations(
                self.config.circuit().scheme(),
                unsafe { self.scheme_context.assume_init_mut() },
                &mut self.wire_contents,
                round,
            )?;
            let (send_len, recv_len) = Self::do_network_operations(
                self.config.circuit().scheme(),
                unsafe { self.scheme_context.assume_init_mut() },
                &mut self.wire_contents,
                &mut self.network,
                round,
            )
            .await?;
            total_send_len += send_len;
            total_recv_len += recv_len;
        }

        self.execution_state = ExecutionState::FinishedOffline;

        Ok((total_send_len, total_recv_len))
    }

    pub fn prepare_input<I>(&mut self, user_inputs: I) -> Result<(), ExecutionContextError>
    where
        I: IntoIterator<Item = (WireId, S::Input)>,
    {
        use std::collections::hash_map::Entry;
        assert_state!(
            "prepare_input",
            self.execution_state,
            ExecutionState::FinishedOffline
        );

        let mut input_wires: HashMap<_, _> = self
            .config
            .circuit()
            .get_input_operation_wire_ids_of_party(self.network.my_id())
            .map(|x| (x, false))
            .collect();

        let mut inputs = Vec::with_capacity(input_wires.len());
        for (wire_id, input) in user_inputs.into_iter() {
            match input_wires.entry(wire_id) {
                Entry::Occupied(mut occupied_entry) if !occupied_entry.get() => {
                    *occupied_entry.get_mut() = true;
                    inputs.push((wire_id, input));
                }
                Entry::Occupied(_) => {
                    return Err(ExecutionContextError::DuplicateInput { wire: wire_id });
                }
                Entry::Vacant(_) => {
                    return Err(ExecutionContextError::InvalidInputWire { wire: wire_id });
                }
            };
        }

        if inputs.len() < input_wires.len() {
            return Err(ExecutionContextError::NotEnoughInputs);
        }

        self.config
            .scheme()
            .prepare_user_input(unsafe { self.scheme_context.assume_init_mut() }, inputs);

        self.execution_state = ExecutionState::ReadyOnline;

        Ok(())
    }

    pub async fn do_online(&mut self) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        assert_state!(
            "do_online",
            self.execution_state,
            ExecutionState::ReadyOnline
        );

        let mut total_send_len = 0;
        let mut total_recv_len = 0;
        for round in self.config.circuit().online_rounds().iter() {
            Self::do_local_operations(
                self.config.circuit().scheme(),
                unsafe { self.scheme_context.assume_init_mut() },
                &mut self.wire_contents,
                round,
            )?;
            let (send_len, recv_len) = Self::do_network_operations(
                self.config.circuit().scheme(),
                unsafe { self.scheme_context.assume_init_mut() },
                &mut self.wire_contents,
                &mut self.network,
                round,
            )
            .await?;

            total_send_len += send_len;
            total_recv_len += recv_len;
        }

        self.execution_state = ExecutionState::Finished;

        Ok((total_send_len, total_recv_len))
    }

    pub fn get_wire(&self, id: WireId) -> Option<&S::Wire> {
        self.wire_contents.get(&id)
    }

    pub fn dump_wires_with_filter<P>(&self, mut predicate: P)
    where
        P: FnMut(&S::Wire) -> bool,
    {
        let to_print = self
            .wire_contents
            .iter()
            .filter(|&(_, wire)| predicate(wire))
            .sorted_by_key(|(id, _)| id.0)
            .map(|(id, wire)| (id.0, wire))
            .collect_vec();

        println!("{:#?}", to_print);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::{
        FinalizePhaseOutput, MpcCircuit, NetworkPhaseOutput, Operation, scheme::MpcScheme,
    };
    use crate::networking::{Network, ReceiveRequest, RecvLen, SendLen, SendRequest};
    use serde::{Deserialize, Serialize};
    use std::convert::Infallible;
    use std::future::Future;
    use std::io;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    enum MockOp {
        Input(usize, WireId),
    }

    impl Operation for MockOp {
        fn get_input_party_id(&self) -> Option<usize> {
            match self {
                MockOp::Input(party, _) => Some(*party),
            }
        }
        fn inputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a> {
            Box::new(std::iter::empty())
        }
        fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a> {
            match self {
                MockOp::Input(_, out) => Box::new(std::iter::once(*out)),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MockScheme;

    impl MpcScheme for MockScheme {
        type Context = ();
        type NetworkElement = ();
        type Wire = ();
        type Input = ();
        type Operation = MockOp;
        type Pending<'a> = ();
        type EstablishContextError = Infallible;
        type NetworkPhaseError = Infallible;
        type FinalizePhaseError = Infallible;
        fn is_circuit_sound<'a, I>(&self, _c: I) -> bool
        where
            Self::Operation: 'a,
            I: IntoIterator<Item = &'a Self::Operation>,
        {
            true
        }
        fn is_operation_local(&self, _op: &Self::Operation) -> bool {
            false
        }
        fn establish_context<N: Network>(
            &self,
            _n: &mut N,
            _c: &MpcCircuit<Self>,
        ) -> Result<Self::Context, Self::EstablishContextError> {
            Ok(())
        }
        fn prepare_user_input<I>(&self, _c: &mut Self::Context, _i: I)
        where
            I: IntoIterator<Item = (WireId, Self::Input)>,
        {
        }
        fn do_network_phase<'a, I>(
            &self,
            _c: &mut Self::Context,
            _o: &Self::Operation,
            _i: I,
        ) -> Result<NetworkPhaseOutput<'a, Self>, Self::NetworkPhaseError>
        where
            Self::Wire: 'a,
            I: IntoIterator<Item = &'a Self::Wire>,
        {
            Ok(NetworkPhaseOutput {
                pending: (),
                send_request: vec![],
                receive_request: vec![],
            })
        }
        fn do_finalize_phase<'a, I>(
            &self,
            _c: &mut Self::Context,
            _p: Self::Pending<'a>,
            _n: I,
        ) -> Result<FinalizePhaseOutput<Self>, Self::FinalizePhaseError>
        where
            I: IntoIterator<Item = Self::NetworkElement>,
        {
            Ok(FinalizePhaseOutput(vec![()]))
        }
    }

    struct MockNetwork {
        n: usize,
        id: usize,
    }
    impl Network for MockNetwork {
        fn n_players(&self) -> usize {
            self.n
        }
        fn my_id(&self) -> usize {
            self.id
        }
        fn send_objects_many<'a, T, I>(
            &mut self,
            _req: I,
        ) -> impl Future<Output = io::Result<SendLen>>
        where
            T: Serialize + Clone + 'a,
            I: IntoIterator<Item = &'a SendRequest<'a, T>>,
        {
            async move { Ok(0) }
        }
        fn send(&mut self, _to: usize, _data: &[u8]) -> impl Future<Output = io::Result<SendLen>> {
            async move { Ok(0) }
        }
        fn broadcast(&mut self, _data: &[u8]) -> impl Future<Output = io::Result<SendLen>> {
            async move { Ok(0) }
        }
        fn recv(&mut self, _from: usize) -> impl Future<Output = io::Result<(Vec<u8>, RecvLen)>> {
            async move { Ok((vec![], 0)) }
        }
        fn recv_objects_many<'a, T, I>(
            &mut self,
            _req: I,
        ) -> impl Future<Output = io::Result<(Vec<Vec<T>>, RecvLen)>>
        where
            T: for<'de> Deserialize<'de> + 'a,
            I: IntoIterator<Item = &'a ReceiveRequest<T>>,
        {
            async move { Ok((vec![], 0)) }
        }
    }

    fn setup(my_id: usize, n: usize) -> ExecutionContext<MockScheme, MockNetwork> {
        let ops = vec![MockOp::Input(0, WireId(0))];
        let circuit = MpcCircuit::new(ops, MockScheme).unwrap();
        let config = MpcConfig::new(my_id, n, circuit).unwrap();
        ExecutionContext::new(config, MockNetwork { n, id: my_id }).unwrap()
    }

    #[test]
    fn test_handshake_mismatch() {
        let ops = vec![MockOp::Input(0, WireId(0))];
        let circuit = MpcCircuit::new(ops, MockScheme).unwrap();
        let config = MpcConfig::new(0, 2, circuit).unwrap(); // expects 2
        let err = match ExecutionContext::new(config, MockNetwork { n: 3, id: 0 }) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        }; // actual 3
        assert!(matches!(
            err,
            ExecutionContextError::InvalidConfiguration { .. }
        ));
    }

    #[tokio::test]
    async fn test_state_machine_order() {
        let mut exec = setup(0, 2);

        // Calling prepare_input before handshake/offline fails
        let err = match exec.prepare_input(vec![]) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, ExecutionContextError::StateError { .. }));

        // Calling do_online before handshake/offline fails
        let err = match exec.do_online().await {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, ExecutionContextError::StateError { .. }));

        exec.handshake().await.unwrap();
        exec.do_offline().await.unwrap();

        // Calling do_offline again fails
        let err = match exec.do_offline().await {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, ExecutionContextError::StateError { .. }));
    }

    #[tokio::test]
    async fn test_input_validation() {
        let mut exec = setup(0, 2); // input belongs to party 0
        exec.handshake().await.unwrap();
        exec.do_offline().await.unwrap();

        // Missing inputs
        let err = match exec.prepare_input(vec![]) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, ExecutionContextError::NotEnoughInputs));

        // Invalid wire id
        let err = match exec.prepare_input(vec![(WireId(0), ()), (WireId(99), ())]) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(
            err,
            ExecutionContextError::InvalidInputWire { wire: WireId(99) }
        ));

        // Duplicate inputs
        let err = match exec.prepare_input(vec![(WireId(0), ()), (WireId(0), ())]) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(
            err,
            ExecutionContextError::DuplicateInput { wire: WireId(0) }
        ));

        // Correct inputs
        exec.prepare_input(vec![(WireId(0), ())]).unwrap();
    }
}
