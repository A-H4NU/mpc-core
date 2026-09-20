impl std::fmt::Display for ExecutionContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration { msg } => write!(f, "Invalid configuration: {}", msg),
            Self::StateError { state, op } => write!(
                f,
                "Execution state error: {} not allowed in state {:?}",
                op, state
            ),
            Self::NetworkError { source } => write!(f, "Network error: {}", source),
            Self::PlanNotAgreed => write!(f, "Plan not agreed between parties"),
            Self::DuplicateInput { wire } => write!(f, "Duplicate input for wire {}", wire),
            Self::InvalidInputWire { wire } => {
                write!(f, "Wire {} is not an output of an input operation", wire)
            }
            Self::NotEnoughInputs => write!(f, "Not enough inputs provided"),
            Self::SchemeError { phase, msg } => write!(f, "Scheme error during {}: {}", phase, msg),
        }
    }
}
impl std::error::Error for ExecutionContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NetworkError { source } => Some(source),
            _ => None,
        }
    }
}
use itertools::Itertools;
use sha3::{Digest, Sha3_512};

/// Enumerates the exhaustive set of failure modalities that can manifest
/// during the execution of a multiparty computation circuit.
#[derive(Debug)]
pub enum ExecutionContextError {
    /// Raised when the configuration matrix provided to the execution context is invalid.
    InvalidConfiguration {
        /// A descriptive diagnostic detailing the exact configuration failure.
        msg: String,
    },
    /// Raised when a phase transition operation is invoked in a non-compliant state.
    StateError {
        /// The stringified identifier of the requested operation.
        op: String,
        /// The current immutable state of the state machine.
        state: ExecutionState,
    },
    /// Raised when asynchronous I/O fails over the network boundary.
    NetworkError {
        /// The underlying POSIX or Tokio I/O error object.
        source: std::io::Error,
    },
    /// Raised when multiparty members possess disparate topology hashes for the circuit.
    PlanNotAgreed,
    /// Raised when a user attempts to populate a circuit input multiple times.
    DuplicateInput {
        /// The identifier of the input wire which was redundantly specified.
        wire: WireId,
    },
    /// Raised when an input assignment targets a wire that is not defined as an input.
    InvalidInputWire {
        /// The identifier of the non-input wire targeted for assignment.
        wire: WireId,
    },
    /// Raised when the protocol requires more input materials than the user supplied.
    NotEnoughInputs,
    /// Raised when the underlying cryptographic scheme aborts dynamically.
    SchemeError {
        /// The chronological phase of the multiparty scheme (e.g. offline, online).
        phase: String,
        /// An associated message from the scheme encapsulating the error semantics.
        msg: String,
    },
}

use std::{collections::HashMap, mem::MaybeUninit};

use crate::{
    mpc::{
        NetworkPhaseOutput, Operation,
        circuit::{Round, WireId},
        scheme::MpcScheme,
    },
    networking::{Network, ReceiveRequest, RecvLen, SendLen},
};

/// Represents the deterministic, discretely bounded states of a multiparty computation.
#[derive(Debug, Clone, Copy)]
pub enum ExecutionState {
    /// Newly instantiated context, untouched by any evaluation logic.
    NewBorn,
    /// Topological synchronization is complete and agreement is proven across peers.
    Handshaked,
    /// The input-independent preprocessing rounds have been successfully computed.
    FinishedOffline,
    /// Private user inputs are materialized and the system is poised for online interaction.
    ReadyOnline,
    /// The directed acyclic graph is fully evaluated and protocol output is available.
    Finished,
}

type WireMap<S> = HashMap<WireId, <S as MpcScheme>::Wire>;

/// The primary state machine managing the lifecycle and evaluation of a multiparty computation.
///
/// Orchestrates the cryptographic scheme context, physical network interface, and evaluation of
/// the topological circuit graph. It bounds the phases of computation securely.
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(all(feature = "example-additive", feature = "example-secure-network"))]
/// # #[tokio::main]
/// # async fn main() {
/// use mpc_core::mpc::{ExecutionContext, MpcCircuit, WireId};
/// use mpc_core::example::additive::{AdditiveScheme, AdditiveOperation};
/// use mpc_core::networking::secure_mesh::{MeshNetwork, NodeIdentity};
/// use ed25519_dalek::SigningKey;
///
/// // 1. Construct the topological circuit and cryptographic scheme
/// let scheme = AdditiveScheme::<100>;
/// let ops = vec![
///     AdditiveOperation::Input { party_id: 0, output: WireId(0) },
///     AdditiveOperation::Input { party_id: 1, output: WireId(1) },
///     AdditiveOperation::Add { left: WireId(0), right: WireId(1), output: WireId(2) }
/// ];
/// let circuit = MpcCircuit::new(ops, scheme).expect("Valid circuit");
///
/// // 2. Establish the secure network transport
/// let sk = SigningKey::from_bytes(&[0u8; 32]);
/// let identity = NodeIdentity {
///     address: "127.0.0.1:8080".parse().unwrap(),
///     public_key: sk.verifying_key()
/// };
/// let mut network = MeshNetwork::from_identities(0, sk, vec![identity.clone(), identity]).await.unwrap();
///
/// // 3. Bind the network and circuit into a synchronized execution context
/// let mut ctx = ExecutionContext::new(circuit, network).unwrap();
///
/// // 4. Execute the distributed computation phases sequentially
/// ctx.handshake().await.unwrap();
/// ctx.do_offline().await.unwrap();
///
/// // 5. Materialize local inputs
/// ctx.prepare_input(vec![(WireId(0), 42)]).unwrap();
///
/// // 6. Evaluate the online dependency graph
/// ctx.do_online().await.unwrap();
///
/// // 7. Retrieve the materialized output logic
/// let result = ctx.get_wire(WireId(2)).unwrap();
/// # }
/// # #[cfg(not(all(feature = "example-additive", feature = "example-secure-network")))]
/// # fn main() {}
/// ```
pub struct ExecutionContext<S, N>
where
    S: MpcScheme,
    N: Network,
{
    circuit: crate::mpc::circuit::MpcCircuit<S>,
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
    /// Constructs a newborn execution context mapping a circuit graph to a network configuration.
    pub fn new(
        circuit: crate::mpc::circuit::MpcCircuit<S>,
        network: N,
    ) -> Result<Self, ExecutionContextError> {
        Ok(Self {
            circuit,
            execution_state: ExecutionState::NewBorn,
            network,
            wire_contents: HashMap::new(),
            scheme_context: MaybeUninit::uninit(),
        })
    }

    /// Exposes an immutable reference to the deterministic state machine pointer.
    pub fn execution_state(&self) -> &ExecutionState {
        &self.execution_state
    }

    /// Cryptographically synchronizes the network nodes and asserts consensus on the directed acyclic graph architecture.
    pub async fn handshake(&mut self) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        assert_state!("handshake", self.execution_state, ExecutionState::NewBorn);

        let mut hasher = Sha3_512::new();
        hasher.update(&postcard::to_stdvec(&&self.circuit).map_err(|e| {
            ExecutionContextError::SchemeError {
                phase: "scheme phase".to_string(),
                msg: e.to_string(),
            }
        })?);
        let hash: Vec<u8> = hasher.finalize().to_vec();

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
            .recv_objects_many::<Vec<u8>, _>(&request)
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
            .circuit
            .scheme()
            .establish_context(&mut self.network, &self.circuit)
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

            for (wire_id, wire_content) in itertools::zip_eq(op.outputs(), output) {
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
            for (wire_id, wire_content) in itertools::zip_eq(op.outputs(), output) {
                let prev = wire_contents.insert(wire_id, wire_content);
                assert!(prev.is_none());
            }
        }

        Ok((send_len, recv_len))
    }

    /// Executes the input-independent cryptographic preprocessing sequence.
    ///
    /// Iterates through the topologically sorted offline rounds, computing local mathematical
    /// operations and resolving network dependencies before inputs are materialized.
    pub async fn do_offline(&mut self) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        assert_state!(
            "do_offline",
            self.execution_state,
            ExecutionState::Handshaked
        );

        let mut total_send_len = 0;
        let mut total_recv_len = 0;
        for round in self.circuit.offline_rounds().iter() {
            Self::do_local_operations(
                self.circuit.scheme(),
                unsafe { self.scheme_context.assume_init_mut() },
                &mut self.wire_contents,
                round,
            )?;
            let (send_len, recv_len) = Self::do_network_operations(
                self.circuit.scheme(),
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

    /// Allocates and validates the secret or public combinatorial inputs provided by the user.
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
            .circuit
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

        self.circuit
            .scheme()
            .prepare_user_input(unsafe { self.scheme_context.assume_init_mut() }, inputs);

        self.execution_state = ExecutionState::ReadyOnline;

        Ok(())
    }

    /// Evaluates the input-dependent computation sequence and resolves the final outputs.
    pub async fn do_online(&mut self) -> Result<(SendLen, RecvLen), ExecutionContextError> {
        assert_state!(
            "do_online",
            self.execution_state,
            ExecutionState::ReadyOnline
        );

        let mut total_send_len = 0;
        let mut total_recv_len = 0;
        for round in self.circuit.online_rounds().iter() {
            Self::do_local_operations(
                self.circuit.scheme(),
                unsafe { self.scheme_context.assume_init_mut() },
                &mut self.wire_contents,
                round,
            )?;
            let (send_len, recv_len) = Self::do_network_operations(
                self.circuit.scheme(),
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

    /// Retrieves an immutable reference to the evaluated wire logic element, if it exists in the
    /// active wire mapping.
    pub fn get_wire(&self, id: WireId) -> Option<&S::Wire> {
        self.wire_contents.get(&id)
    }

    /// Evaluates a predicate over all computed wires, dumping satisfying wire data for heuristic
    /// debugging.
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
    use crate::mpc::{MpcCircuit, NetworkPhaseOutput, Operation, scheme::MpcScheme};
    use crate::networking::{Network, RecvLen, SendLen, SendRequest};
    use serde::{Deserialize, Serialize};
    use std::convert::Infallible;
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
        ) -> Result<Vec<Self::Wire>, Self::FinalizePhaseError>
        where
            I: IntoIterator<Item = Self::NetworkElement>,
        {
            Ok(vec![()])
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
        async fn send_objects_many<'a, T, I>(&mut self, _req: I) -> io::Result<SendLen>
        where
            T: Serialize + Clone + 'a,
            I: IntoIterator<Item = &'a SendRequest<'a, T>>,
        {
            Ok(0)
        }
        async fn send(&mut self, _to: usize, _data: &[u8]) -> io::Result<SendLen> {
            Ok(0)
        }
        async fn broadcast(&mut self, _data: &[u8]) -> io::Result<SendLen> {
            Ok(0)
        }
        async fn recv(&mut self, _from: usize) -> io::Result<(Vec<u8>, RecvLen)> {
            Ok((vec![], 0))
        }
        async fn recv_objects_many<'a, T, I>(
            &mut self,
            _req: I,
        ) -> io::Result<(Vec<Vec<T>>, RecvLen)> {
            Ok((vec![], 0))
        }
    }

    fn setup(my_id: usize, n: usize) -> ExecutionContext<MockScheme, MockNetwork> {
        let ops = vec![MockOp::Input(0, WireId(0))];
        let circuit = MpcCircuit::new(ops, MockScheme).unwrap();
        ExecutionContext::new(circuit, MockNetwork { n, id: my_id }).unwrap()
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
