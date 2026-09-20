use std::{
    collections::{HashMap, VecDeque},
    fmt,
};

use crate::mpc::{Operation, scheme::MpcScheme};
use serde::{Deserialize, Serialize};
use snafu::{Snafu, ensure};

/// An identifier for a wire within a directed acyclic graph representing a multi-party computation circuit.
///
/// Every wire uniquely connects the output of one cryptographic operation to the input of another.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct WireId(pub usize);

impl fmt::Display for WireId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A discrete synchronization step in the multi-party computation protocol.
///
/// Operations within a single round are topologically independent and can be executed concurrently.
/// A round is strictly partitioned into local computation operations (requiring no network interaction)
/// and network operations (requiring interaction across the cluster).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round<S: MpcScheme> {
    local_operations: Vec<S::Operation>,
    network_operations: Vec<S::Operation>,
}

impl<S: MpcScheme> Round<S> {
    /// Returns a slice of the local operations scheduled for this round.
    pub fn local_operations(&self) -> &[S::Operation] {
        &self.local_operations
    }

    /// Returns a slice of the network-dependent operations scheduled for this round.
    pub fn network_operations(&self) -> &[S::Operation] {
        &self.network_operations
    }
}

/// A structured execution plan for a cryptographic multi-party computation protocol.
///
/// The circuit encapsulates the specific sequence of operations required to securely compute
/// a function. It partitions a logical directed acyclic graph of operations into discrete
/// sequential rounds. The execution is bifurcated into an offline phase (input-independent)
/// and an online phase (input-dependent) to optimize communication overhead.
///
/// # Examples
///
/// ```
/// use mpc_core::mpc::MpcCircuit;
/// use mpc_core::mpc::WireId;
/// # #[cfg(feature = "example-additive")]
/// # {
/// use mpc_core::example::additive::{AdditiveScheme, AdditiveOperation};
///
/// let ops = vec![
///     AdditiveOperation::Input { party_id: 0, output: WireId(0) },
///     AdditiveOperation::Input { party_id: 1, output: WireId(1) },
///     AdditiveOperation::Add { left: WireId(0), right: WireId(1), output: WireId(2) },
/// ];
/// let scheme = AdditiveScheme::<100>;
/// let circuit = MpcCircuit::new(ops, scheme).unwrap();
/// assert_eq!(circuit.num_total_rounds(), 3);
/// # }
/// ```
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "S: MpcScheme")]
pub struct MpcCircuit<S: MpcScheme> {
    scheme: S,
    offline_rounds: Vec<Round<S>>,
    online_rounds: Vec<Round<S>>,
}

/// Errors that can occur during the instantiation and topological sorting of an [`MpcCircuit`].
#[derive(Debug, Snafu)]
pub enum MpcCircuitError {
    #[snafu(display("The provided circuit is not sound"))]
    CircuitUnsound,
    #[snafu(display("Wire {wire} produced multiple times"))]
    WireProducedManyTimes { wire: WireId },
    #[snafu(display("Wire {wire} is consumed but it is never produced"))]
    WireConsumedButNotProduced { wire: WireId },
    #[snafu(display("Circuit is cyclic"))]
    CircuitCyclic,
    #[snafu(display("Circuit is empty"))]
    EmptyCircuit,
}

impl<S: MpcScheme> MpcCircuit<S> {
    /// Constructs a new multi-party computation circuit.
    ///
    /// The constructor performs a topological sort on the provided operations to resolve dependencies,
    /// batching them into sequentially executed rounds. It partitions operations into an offline wave
    /// and an online wave based on dependency on user inputs.
    ///
    /// [PLACEHOLDER for Panics: cryptographic assertion placeholders]
    pub fn new<I>(operations: I, scheme: S) -> Result<Self, MpcCircuitError>
    where
        I: IntoIterator<Item = S::Operation>,
    {
        let raw_ops = operations.into_iter().collect::<Vec<_>>();
        let num_ops = raw_ops.len();

        ensure!(num_ops > 0, EmptyCircuitSnafu);
        ensure!(scheme.is_circuit_sound(&raw_ops), CircuitUnsoundSnafu);

        let (mut ops, adj, mut in_degree) = {
            let mut adj: Vec<Vec<usize>> = vec![vec![]; num_ops];
            let mut in_degree: Vec<usize> = vec![0; num_ops];
            let mut wire_producer: HashMap<WireId, usize> = HashMap::new();

            for (idx, op) in raw_ops.iter().enumerate() {
                for out_wire in op.outputs() {
                    let prev = wire_producer.insert(out_wire, idx);
                    if prev.is_some() {
                        return Err(MpcCircuitError::WireProducedManyTimes { wire: out_wire });
                    }
                }
            }

            for (consumer_idx, op) in raw_ops.iter().enumerate() {
                for input_wire in op.inputs() {
                    if let Some(&producer_idx) = wire_producer.get(&input_wire) {
                        adj[producer_idx].push(consumer_idx);
                        in_degree[consumer_idx] += 1;
                    } else {
                        return Err(MpcCircuitError::WireConsumedButNotProduced {
                            wire: input_wire,
                        });
                    }
                }
            }
            let ops: Vec<_> = raw_ops.into_iter().map(Some).collect();
            (ops, adj, in_degree)
        };

        let mut offline_rounds: Vec<Round<S>> = Vec::new();
        let mut online_rounds: Vec<Round<S>> = Vec::new();

        let mut offline_wave: VecDeque<_> = in_degree
            .iter()
            .enumerate()
            .filter_map(|(idx, deg)| (*deg == 0).then_some(idx))
            .collect();
        let mut online_wave = VecDeque::new();

        let mut process_wave =
            |wave: &mut VecDeque<usize>,
             rounds: &mut Vec<Round<S>>,
             mut target_online_wave: Option<&mut VecDeque<usize>>| {
                while !wave.is_empty() {
                    let mut next_wave = VecDeque::new();
                    let mut local_operations = Vec::new();
                    let mut network_operations = Vec::new();

                    while let Some(op_idx) = wave.pop_front() {
                        if let Some(ref mut online_w) = target_online_wave
                            && ops[op_idx].as_ref().unwrap().is_input()
                        {
                            online_w.push_back(op_idx);
                            continue;
                        }

                        let op = ops[op_idx].take().unwrap();
                        let op_local = scheme.is_operation_local(&op);

                        if op_local {
                            local_operations.push(op);
                        } else {
                            network_operations.push(op);
                        }

                        for &consumer_idx in &adj[op_idx] {
                            in_degree[consumer_idx] -= 1;
                            if in_degree[consumer_idx] == 0 {
                                if op_local {
                                    wave.push_back(consumer_idx);
                                } else {
                                    next_wave.push_back(consumer_idx);
                                }
                            }
                        }
                    }

                    rounds.push(Round {
                        local_operations,
                        network_operations,
                    });

                    std::mem::swap(wave, &mut next_wave);
                }
            };

        process_wave(
            &mut offline_wave,
            &mut offline_rounds,
            Some(&mut online_wave),
        );
        process_wave(&mut online_wave, &mut online_rounds, None);

        if ops.iter().any(Option::is_some) {
            return Err(MpcCircuitError::CircuitCyclic);
        }

        debug_assert!(offline_rounds.iter().all(|round| {
            round.network_operations.iter().all(|op| !op.is_input())
                && round.local_operations.iter().all(|op| !op.is_input())
        }));

        debug_assert!(
            online_rounds
                .iter()
                .all(|round| { round.local_operations.iter().all(|op| !op.is_input()) })
        );

        Ok(MpcCircuit {
            scheme,
            offline_rounds,
            online_rounds,
        })
    }

    /// Returns an iterator over the wire identifiers corresponding to the input operations provided by the specified party.
    pub fn get_input_operation_wire_ids_of_party(
        &self,
        party_id: usize,
    ) -> impl Iterator<Item = WireId> {
        self.online_rounds
            .iter()
            .flat_map(|round| round.network_operations.iter())
            .filter(move |op| op.get_input_party_id() == Some(party_id))
            .map(|op| op.outputs().next().expect("Expected one output"))
    }

    /// Returns a reference to the underlying cryptographic scheme.
    pub fn scheme(&self) -> &S {
        &self.scheme
    }

    /// Returns a slice of the online rounds scheduled for this circuit.
    pub fn online_rounds(&self) -> &[Round<S>] {
        &self.online_rounds
    }

    /// Returns a slice of the offline rounds scheduled for this circuit.
    pub fn offline_rounds(&self) -> &[Round<S>] {
        &self.offline_rounds
    }

    /// Returns the total number of rounds in both the offline and online phases.
    pub fn num_total_rounds(&self) -> usize {
        self.offline_rounds.len() + self.online_rounds.len()
    }

    /// Returns the number of rounds dedicated to the offline phase.
    pub fn num_offline_rounds(&self) -> usize {
        self.offline_rounds.len()
    }

    pub fn num_online_rounds(&self) -> usize {
        self.online_rounds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::NetworkPhaseOutput;
    use crate::networking::Network;
    use std::convert::Infallible;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    enum MockOp {
        Input(usize, WireId),
        Local(Vec<WireId>, WireId),
        Network(Vec<WireId>, WireId),
    }

    impl Operation for MockOp {
        fn get_input_party_id(&self) -> Option<usize> {
            match self {
                MockOp::Input(party, _) => Some(*party),
                _ => None,
            }
        }
        fn inputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a> {
            match self {
                MockOp::Input(_, _) => Box::new(std::iter::empty()),
                MockOp::Local(ins, _) | MockOp::Network(ins, _) => {
                    Box::new(ins.clone().into_iter())
                }
            }
        }
        fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a> {
            match self {
                MockOp::Input(_, out) | MockOp::Local(_, out) | MockOp::Network(_, out) => {
                    Box::new(std::iter::once(*out))
                }
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

        fn is_circuit_sound<'a, I>(&self, _circuit: I) -> bool
        where
            Self::Operation: 'a,
            I: IntoIterator<Item = &'a Self::Operation>,
        {
            true
        }

        fn is_operation_local(&self, op: &Self::Operation) -> bool {
            matches!(op, MockOp::Local(_, _))
        }

        fn establish_context<N: Network>(
            &self,
            _network: &mut N,
            _circuit: &MpcCircuit<Self>,
        ) -> Result<Self::Context, Self::EstablishContextError> {
            Ok(())
        }

        fn prepare_user_input<I>(&self, _context: &mut Self::Context, _inputs: I)
        where
            I: IntoIterator<Item = (WireId, Self::Input)>,
        {
        }

        fn do_network_phase<'a, I>(
            &self,
            _context: &mut Self::Context,
            _op: &Self::Operation,
            _inputs: I,
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
            _context: &mut Self::Context,
            _pending: Self::Pending<'a>,
            _network_data: I,
        ) -> Result<Vec<Self::Wire>, Self::FinalizePhaseError>
        where
            I: IntoIterator<Item = Self::NetworkElement>,
        {
            Ok(vec![()])
        }
    }

    #[test]
    fn test_offline_and_online_rounds() {
        let ops = vec![
            MockOp::Local(vec![], WireId(0)),
            MockOp::Local(vec![], WireId(1)),
            MockOp::Network(vec![WireId(0), WireId(1)], WireId(2)),
            MockOp::Input(0, WireId(3)),
            MockOp::Local(vec![WireId(3)], WireId(4)),
            MockOp::Network(vec![WireId(2), WireId(4)], WireId(5)),
        ];

        let circuit = MpcCircuit::new(ops, MockScheme).unwrap();

        let offline = circuit.offline_rounds();
        assert_eq!(offline.len(), 1);

        assert_eq!(offline[0].local_operations().len(), 2);
        assert_eq!(offline[0].network_operations().len(), 1);
        assert_eq!(
            offline[0].network_operations()[0],
            MockOp::Network(vec![WireId(0), WireId(1)], WireId(2))
        );

        let online = circuit.online_rounds();
        assert_eq!(online.len(), 2);

        assert_eq!(online[0].local_operations().len(), 0);
        assert_eq!(online[0].network_operations().len(), 1);
        assert_eq!(
            online[0].network_operations()[0],
            MockOp::Input(0, WireId(3))
        );

        assert_eq!(online[1].local_operations().len(), 1);
        assert_eq!(
            online[1].local_operations()[0],
            MockOp::Local(vec![WireId(3)], WireId(4))
        );
        assert_eq!(online[1].network_operations().len(), 1);
        assert_eq!(
            online[1].network_operations()[0],
            MockOp::Network(vec![WireId(2), WireId(4)], WireId(5))
        );
    }

    #[test]
    fn test_empty_circuit() {
        let err = match MpcCircuit::new(Vec::<MockOp>::new(), MockScheme) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, MpcCircuitError::EmptyCircuit));
    }

    #[test]
    fn test_unsound_circuit() {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct UnsoundScheme;
        impl MpcScheme for UnsoundScheme {
            type Context = ();
            type NetworkElement = ();
            type Wire = ();
            type Input = ();
            type Operation = MockOp;
            type Pending<'a> = ();
            type EstablishContextError = Infallible;
            type NetworkPhaseError = Infallible;
            type FinalizePhaseError = Infallible;
            fn is_circuit_sound<'a, I>(&self, _circuit: I) -> bool
            where
                Self::Operation: 'a,
                I: IntoIterator<Item = &'a Self::Operation>,
            {
                false
            }
            fn is_operation_local(&self, _op: &Self::Operation) -> bool {
                true
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
                Ok(vec![])
            }
        }
        let ops = vec![MockOp::Local(vec![], WireId(0))];
        let err = match MpcCircuit::new(ops, UnsoundScheme) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, MpcCircuitError::CircuitUnsound));
    }

    #[test]
    fn test_wire_produced_many_times() {
        let ops = vec![
            MockOp::Local(vec![], WireId(1)),
            MockOp::Local(vec![], WireId(1)),
        ];
        let err = match MpcCircuit::new(ops, MockScheme) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(
            err,
            MpcCircuitError::WireProducedManyTimes { wire: WireId(1) }
        ));
    }

    #[test]
    fn test_wire_consumed_but_not_produced() {
        let ops = vec![MockOp::Local(vec![WireId(99)], WireId(1))];
        let err = match MpcCircuit::new(ops, MockScheme) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(
            err,
            MpcCircuitError::WireConsumedButNotProduced { wire: WireId(99) }
        ));
    }

    #[test]
    fn test_circuit_cyclic() {
        let ops = vec![
            MockOp::Local(vec![WireId(2)], WireId(1)),
            MockOp::Local(vec![WireId(1)], WireId(2)),
        ];
        let err = match MpcCircuit::new(ops, MockScheme) {
            Err(e) => e,
            Ok(_) => panic!("Expected error"),
        };
        assert!(matches!(err, MpcCircuitError::CircuitCyclic));
    }
}
