use itertools::Itertools;
use sha3::{Digest, Sha3_512, digest::generic_array::GenericArray};
use snafu::{self, ResultExt, Whatever};
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

#[derive(Debug)]
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
        assert!(
            matches!($state_var, $state_pat),
            concat!(
                "`ExecutionContext::",
                $fn_name,
                "` must be called when `ExecutionContext::execution_state` is `",
                stringify!($state_pat),
                "`"
            )
        )
    };
}

impl<S, N> ExecutionContext<S, N>
where
    S: MpcScheme,
    N: Network,
{
    pub fn new(config: MpcConfig<S>, network: N) -> Result<Self, Whatever> {
        if config.n_parties() != network.n_players() {
            snafu::whatever!("#parties mismatch");
        }
        if config.my_id() != network.my_id() {
            snafu::whatever!("Id mismatch");
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

    pub async fn handshake(&mut self) -> Result<(SendLen, RecvLen), Whatever> {
        fn ctx<E: std::error::Error>(_: &mut E) -> String {
            "Handshake error".to_string()
        }

        assert_state!("handshake", self.execution_state, ExecutionState::NewBorn);

        let mut hasher = Sha3_512::new();
        hasher.update(&postcard::to_stdvec(&self.config.circuit()).with_whatever_context(ctx)?);
        let hash = hasher.finalize();

        let send_len = self
            .network
            .broadcast_object(&hash)
            .await
            .with_whatever_context(ctx)?;

        let my_id = self.network.my_id();
        let request: Vec<_> = (0..self.network.n_players())
            .filter(|from| *from != my_id)
            .map(|from| ReceiveRequest::new(from, 1))
            .collect();

        let (hashes, recv_len) = self
            .network
            .recv_objects_many::<GenericArray<_, _>, _>(&request)
            .await
            .with_whatever_context(ctx)?;

        if hashes
            .into_iter()
            .any(|x| x.into_iter().next().unwrap() != hash)
        {
            snafu::whatever!("Plan not agreed");
        }

        let context = self
            .config
            .scheme()
            .establish_context(&mut self.network, self.config.circuit())
            .with_whatever_context(ctx)?;
        self.scheme_context = MaybeUninit::new(context);

        self.execution_state = ExecutionState::Handshaked;
        Ok((send_len, recv_len))
    }

    fn do_local_operations(
        scheme: &S,
        context: &mut S::Context,
        wire_contents: &mut WireMap<S>,
        round: &Round<S>,
    ) -> Result<(), Whatever> {
        fn ctx<E: std::error::Error>(_: &mut E) -> String {
            "Local operation error".to_string()
        }

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
            } = scheme
                .do_network_phase(context, op, inputs)
                .with_whatever_context(ctx)?;
            assert!(send_request.is_empty());
            assert!(receive_request.is_empty());

            let output = scheme
                .do_finalize_phase(context, pending, Vec::new())
                .with_whatever_context(ctx)?;

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
    ) -> Result<(SendLen, RecvLen), Whatever> {
        fn ctx<E: std::error::Error>(_: &mut E) -> String {
            "Network operation error".to_string()
        }

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
            } = scheme
                .do_network_phase(context, op, inputs)
                .with_whatever_context(ctx)?;

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
            .with_whatever_context(ctx)?;

        let (flat_network_data, recv_len) = network
            .recv_objects_many::<S::NetworkElement, _>(&all_receive_requests)
            .await
            .with_whatever_context(ctx)?;

        let mut data_iter = flat_network_data.into_iter();

        let mut buffered_results = Vec::with_capacity(ops.len());
        for (op, pending, req_count) in
            itertools::izip!(ops, pending_ops.into_iter(), receive_request_counts)
        {
            let op_data: Vec<_> = data_iter.by_ref().take(req_count).flatten().collect();
            let output = scheme
                .do_finalize_phase(context, pending, op_data)
                .with_whatever_context(ctx)?;
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

    pub async fn do_offline(&mut self) -> Result<(SendLen, RecvLen), Whatever> {
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

    pub fn prepare_input<I>(&mut self, user_inputs: I) -> Result<(), Whatever>
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
                Entry::Occupied(_) => snafu::whatever!("Duplicate input for wire {}", wire_id),
                Entry::Vacant(_) => {
                    snafu::whatever!("Wire {} is not an output of an input operation", wire_id)
                }
            };
        }

        if inputs.len() < input_wires.len() {
            snafu::whatever!("Not enough inputs are provided");
        }

        self.config
            .scheme()
            .prepare_user_input(unsafe { self.scheme_context.assume_init_mut() }, inputs);

        self.execution_state = ExecutionState::ReadyOnline;

        Ok(())
    }

    pub async fn do_online(&mut self) -> Result<(SendLen, RecvLen), Whatever> {
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

    pub fn dump_wires_with_filter<P>(&self, mut predicate: P)
    where
        P: FnMut(&S::Wire) -> bool,
    {
        use std::{cmp, fmt};
        #[allow(unused)]
        struct Dummy1<'a, S: MpcScheme> {
            id: WireId,
            wire: &'a S::Wire,
        }

        impl<'a, S: MpcScheme> PartialEq for Dummy1<'a, S> {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
            }
        }

        impl<'a, S: MpcScheme> Eq for Dummy1<'a, S> {}

        impl<'a, S: MpcScheme> cmp::PartialOrd for Dummy1<'a, S> {
            fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl<'a, S: MpcScheme> cmp::Ord for Dummy1<'a, S> {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.id.0.cmp(&other.id.0)
            }
        }

        struct Dummy2<'a, S: MpcScheme>(Vec<Dummy1<'a, S>>);

        impl<'a, S: MpcScheme> fmt::Debug for Dummy2<'a, S> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_map()
                    .entries(self.0.iter().map(|d| (d.id.0, d.wire)))
                    .finish()
            }
        }

        let to_print = self
            .wire_contents
            .iter()
            .filter_map(move |(&id, wire)| predicate(wire).then_some(Dummy1::<S> { id, wire }))
            .sorted_unstable()
            .collect_vec();

        println!("{:#?}", Dummy2(to_print));
    }
}
