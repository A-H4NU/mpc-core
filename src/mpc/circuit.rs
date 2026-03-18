use std::{
    collections::{HashMap, VecDeque},
    fmt,
};

use crate::mpc::{Operation, scheme::MpcScheme};
use serde::{Deserialize, Serialize};
use snafu::{Snafu, ensure};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct WireId(pub usize);

impl fmt::Display for WireId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round<S: MpcScheme> {
    local_operations: Vec<S::Operation>,
    network_operations: Vec<S::Operation>,
}

impl<S: MpcScheme> Round<S> {
    pub fn local_operations(&self) -> &[S::Operation] {
        &self.local_operations
    }

    pub fn network_operations(&self) -> &[S::Operation] {
        &self.network_operations
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "S: MpcScheme")]
pub struct MpcCircuit<S: MpcScheme> {
    scheme: S,
    offline_rounds: Vec<Round<S>>,
    online_rounds: Vec<Round<S>>,
}

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

        while !offline_wave.is_empty() {
            let mut next_offline_wave = VecDeque::new();
            let mut local_operations = Vec::new();
            let mut network_operations = Vec::new();

            while let Some(op_idx) = offline_wave.pop_front() {
                if ops[op_idx].as_ref().unwrap().is_input() {
                    online_wave.push_back(op_idx);
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
                            offline_wave.push_back(consumer_idx);
                        } else {
                            next_offline_wave.push_back(consumer_idx);
                        }
                    }
                }
            }

            offline_rounds.push(Round {
                local_operations,
                network_operations,
            });

            std::mem::swap(&mut offline_wave, &mut next_offline_wave);
        }

        while !online_wave.is_empty() {
            let mut next_online_wave = VecDeque::new();
            let mut local_operations = Vec::new();
            let mut network_operations = Vec::new();

            while let Some(op_idx) = online_wave.pop_front() {
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
                            online_wave.push_back(consumer_idx);
                        } else {
                            next_online_wave.push_back(consumer_idx);
                        }
                    }
                }
            }

            online_rounds.push(Round {
                local_operations,
                network_operations,
            });

            std::mem::swap(&mut online_wave, &mut next_online_wave);
        }

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

    pub fn scheme(&self) -> &S {
        &self.scheme
    }

    pub fn online_rounds(&self) -> &[Round<S>] {
        &self.online_rounds
    }

    pub fn offline_rounds(&self) -> &[Round<S>] {
        &self.offline_rounds
    }

    pub fn num_total_rounds(&self) -> usize {
        self.offline_rounds.len() + self.online_rounds.len()
    }

    pub fn num_offline_rounds(&self) -> usize {
        self.offline_rounds.len()
    }

    pub fn num_online_rounds(&self) -> usize {
        self.online_rounds.len()
    }
}
