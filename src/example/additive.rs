use crate::mpc::{
    FinalizePhaseOutput, MpcCircuit, MpcScheme, NetworkPhaseOutput, Operation, WireId,
};
use crate::networking::{Network, ReceiveRequest, SendRequest};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdditiveOperation {
    Input {
        party_id: usize,
        output: WireId,
    },
    GenRandom {
        output: WireId,
    },
    Add {
        left: WireId,
        right: WireId,
        output: WireId,
    },
    Reveal {
        input: WireId,
        output: WireId,
    },
}

impl Operation for AdditiveOperation {
    fn get_input_party_id(&self) -> Option<usize> {
        match self {
            Self::Input { party_id, .. } => Some(*party_id),
            _ => None,
        }
    }

    fn inputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a> {
        match self {
            Self::Input { .. } | Self::GenRandom { .. } => Box::new(std::iter::empty()),
            Self::Add { left, right, .. } => {
                Box::new(std::iter::once(*left).chain(std::iter::once(*right)))
            }
            Self::Reveal { input, .. } => Box::new(std::iter::once(*input)),
        }
    }

    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a> {
        match self {
            Self::Input { output, .. }
            | Self::GenRandom { output, .. }
            | Self::Add { output, .. }
            | Self::Reveal { output, .. } => Box::new(std::iter::once(*output)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditiveScheme<const M: u64>;

#[derive(Debug)]
pub struct AdditiveContext {
    my_id: usize,
    n_players: usize,
    user_inputs: std::collections::HashMap<WireId, u64>,
}

#[derive(Debug)]
pub enum AdditivePending {
    Input {
        is_inputter: bool,
        my_share: Option<u64>,
    },
    GenRandom {
        my_share: u64,
    },
    Add {
        my_share: u64,
    },
    Reveal {
        my_share: u64,
    },
}

impl<const M: u64> MpcScheme for AdditiveScheme<M> {
    type Context = AdditiveContext;
    type NetworkElement = u64;
    type Wire = u64;
    type Input = u64;
    type Operation = AdditiveOperation;
    type Pending<'a> = AdditivePending;

    type EstablishContextError = Infallible;
    type NetworkPhaseError = Infallible;
    type FinalizePhaseError = Infallible;

    fn is_circuit_sound<'a, I>(&self, circuit: I) -> bool
    where
        Self::Operation: 'a,
        I: IntoIterator<Item = &'a Self::Operation>,
    {
        if M == 0 {
            return false;
        }

        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum WireType {
            Shared,
            Public,
        }

        let ops: Vec<_> = circuit.into_iter().collect();
        let mut wire_types = std::collections::HashMap::new();
        let mut changed = true;

        while changed {
            changed = false;
            for op in &ops {
                let new_type = match op {
                    AdditiveOperation::Input { .. } | AdditiveOperation::GenRandom { .. } => {
                        Some(WireType::Shared)
                    }
                    AdditiveOperation::Add { left, right, .. } => {
                        let t1 = wire_types.get(left).copied();
                        let t2 = wire_types.get(right).copied();
                        match (t1, t2) {
                            (Some(WireType::Public), Some(WireType::Public)) => {
                                Some(WireType::Public)
                            }
                            (Some(_), Some(_)) => Some(WireType::Shared),
                            _ => None,
                        }
                    }
                    AdditiveOperation::Reveal { .. } => Some(WireType::Public),
                };

                if let Some(ty) = new_type {
                    for out in op.outputs() {
                        if wire_types.insert(out, ty) != Some(ty) {
                            changed = true;
                        }
                    }
                }
            }
        }

        true
    }

    fn is_operation_local(&self, op: &Self::Operation) -> bool {
        matches!(
            op,
            AdditiveOperation::Add { .. } | AdditiveOperation::GenRandom { .. }
        )
    }

    fn establish_context<N: Network>(
        &self,
        network: &mut N,
        _circuit: &MpcCircuit<Self>,
    ) -> Result<Self::Context, Self::EstablishContextError> {
        Ok(AdditiveContext {
            my_id: network.my_id(),
            n_players: network.n_players(),
            user_inputs: std::collections::HashMap::new(),
        })
    }

    fn prepare_user_input<I>(&self, context: &mut Self::Context, inputs: I)
    where
        I: IntoIterator<Item = (WireId, Self::Input)>,
    {
        for (wire_id, val) in inputs {
            context.user_inputs.insert(wire_id, val % M);
        }
    }

    fn do_network_phase<'a, I>(
        &self,
        context: &mut Self::Context,
        op: &Self::Operation,
        inputs: I,
    ) -> Result<NetworkPhaseOutput<'a, Self>, Self::NetworkPhaseError>
    where
        Self::Wire: 'a,
        I: IntoIterator<Item = &'a Self::Wire>,
    {
        let mut send_request = Vec::new();
        let mut receive_request = Vec::new();
        let mut inputs_iter = inputs.into_iter();
        let mut rng = rand::thread_rng();

        let pending = match op {
            AdditiveOperation::Input { party_id, output } => {
                if context.my_id == *party_id {
                    let input_val = context.user_inputs.remove(output).unwrap_or(0) % M;
                    let mut sum: u64 = 0;
                    for i in 0..context.n_players {
                        if i == context.my_id {
                            continue;
                        }
                        let share = rng.gen_range(0..M);
                        sum = (sum + share) % M;
                        send_request.push(SendRequest::new(i, share));
                    }
                    let my_share = (input_val + M - sum) % M;
                    AdditivePending::Input {
                        is_inputter: true,
                        my_share: Some(my_share),
                    }
                } else {
                    receive_request.push(ReceiveRequest::new(*party_id, 1));
                    AdditivePending::Input {
                        is_inputter: false,
                        my_share: None,
                    }
                }
            }
            AdditiveOperation::GenRandom { .. } => {
                let my_share = rng.gen_range(0..M);
                AdditivePending::GenRandom { my_share }
            }
            AdditiveOperation::Add { .. } => {
                let left = *inputs_iter.next().unwrap();
                let right = *inputs_iter.next().unwrap();
                let my_share = (left + right) % M;
                AdditivePending::Add { my_share }
            }
            AdditiveOperation::Reveal { .. } => {
                let my_share = *inputs_iter.next().unwrap();
                for i in 0..context.n_players {
                    if i == context.my_id {
                        continue;
                    }
                    send_request.push(SendRequest::new(i, my_share));
                }
                for i in 0..context.n_players {
                    if i == context.my_id {
                        continue;
                    }
                    receive_request.push(ReceiveRequest::new(i, 1));
                }
                AdditivePending::Reveal { my_share }
            }
        };

        Ok(NetworkPhaseOutput {
            pending,
            send_request,
            receive_request,
        })
    }

    fn do_finalize_phase<'a, I>(
        &self,
        _context: &mut Self::Context,
        pending: Self::Pending<'a>,
        network_data: I,
    ) -> Result<FinalizePhaseOutput<Self>, Self::FinalizePhaseError>
    where
        I: IntoIterator<Item = Self::NetworkElement>,
    {
        let mut network_data_iter = network_data.into_iter();
        match pending {
            AdditivePending::Input {
                is_inputter,
                my_share,
            } => {
                let share = if is_inputter {
                    my_share.expect("Expected my_share for inputter")
                } else {
                    network_data_iter
                        .next()
                        .expect("Expected share from inputter")
                        % M
                };
                Ok(FinalizePhaseOutput(vec![share]))
            }
            AdditivePending::GenRandom { my_share } | AdditivePending::Add { my_share } => {
                Ok(FinalizePhaseOutput(vec![my_share]))
            }
            AdditivePending::Reveal { my_share } => {
                let mut total = my_share;
                for received in network_data_iter {
                    total = (total + received) % M;
                }
                Ok(FinalizePhaseOutput(vec![total]))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_properties() {
        let op_input = AdditiveOperation::Input {
            party_id: 1,
            output: WireId(0),
        };
        assert_eq!(op_input.get_input_party_id(), Some(1));
        assert!(op_input.is_input());
        assert_eq!(op_input.inputs().count(), 0);
        assert_eq!(op_input.outputs().collect::<Vec<_>>(), vec![WireId(0)]);

        let op_add = AdditiveOperation::Add {
            left: WireId(0),
            right: WireId(1),
            output: WireId(2),
        };
        assert_eq!(op_add.get_input_party_id(), None);
        assert!(!op_add.is_input());
        assert_eq!(
            op_add.inputs().collect::<Vec<_>>(),
            vec![WireId(0), WireId(1)]
        );
        assert_eq!(op_add.outputs().collect::<Vec<_>>(), vec![WireId(2)]);

        let op_reveal = AdditiveOperation::Reveal {
            input: WireId(2),
            output: WireId(3),
        };
        assert_eq!(op_reveal.inputs().collect::<Vec<_>>(), vec![WireId(2)]);
        assert_eq!(op_reveal.outputs().collect::<Vec<_>>(), vec![WireId(3)]);
    }

    #[test]
    fn test_scheme_locality() {
        let scheme = AdditiveScheme::<1000>;
        assert!(!scheme.is_operation_local(&AdditiveOperation::Input {
            party_id: 0,
            output: WireId(0)
        }));
        assert!(scheme.is_operation_local(&AdditiveOperation::Add {
            left: WireId(0),
            right: WireId(1),
            output: WireId(2)
        }));
        assert!(!scheme.is_operation_local(&AdditiveOperation::Reveal {
            input: WireId(2),
            output: WireId(3)
        }));
        assert!(scheme.is_operation_local(&AdditiveOperation::GenRandom { output: WireId(4) }));
    }

    #[test]
    fn test_is_circuit_sound() {
        let scheme = AdditiveScheme::<1000>;

        let ops = vec![
            AdditiveOperation::Input {
                party_id: 0,
                output: WireId(0),
            },
            AdditiveOperation::Input {
                party_id: 1,
                output: WireId(1),
            },
            AdditiveOperation::Add {
                left: WireId(0),
                right: WireId(1),
                output: WireId(2),
            },
            AdditiveOperation::Reveal {
                input: WireId(2),
                output: WireId(3),
            },
        ];
        assert!(scheme.is_circuit_sound(&ops));

        let ops = vec![
            AdditiveOperation::Input {
                party_id: 0,
                output: WireId(0),
            },
            AdditiveOperation::Reveal {
                input: WireId(0),
                output: WireId(1),
            },
            AdditiveOperation::Add {
                left: WireId(1),
                right: WireId(0),
                output: WireId(2),
            },
        ];
        assert!(scheme.is_circuit_sound(&ops));

        let scheme_0 = AdditiveScheme::<0>;
        let ops = vec![AdditiveOperation::Input {
            party_id: 0,
            output: WireId(0),
        }];
        assert!(!scheme_0.is_circuit_sound(&ops));
    }
}

#[cfg(all(test, feature = "example-secure-network"))]
mod secure_network_tests {
    use super::*;
    use crate::mpc::{ExecutionContext, MpcCircuit, MpcConfig, WireId};
    use crate::networking::secure_mesh::{MeshNetwork, NodeIdentities, NodeIdentity};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_additive_mpc_3_parties() {
        let n_parties = 3;
        const M_VAL: u64 = 100;
        let scheme = AdditiveScheme::<M_VAL>;

        let mut signing_keys = Vec::new();
        let mut identities = Vec::new();

        // Find available ports first or just use a fixed range that's likely free.
        // Actually MeshNetwork::from_identities binds to the address.
        // To be safer in tests, let's use 127.0.0.1 with random ports.

        for _ in 0..n_parties {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = sk.verifying_key();
            // We use a hacky way to find free ports by binding to 0 and then dropping.
            // This is still racey but better than fixed ports.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);

            signing_keys.push(sk);
            identities.push(NodeIdentity {
                address: addr,
                public_key: vk,
            });
        }
        let node_identities = NodeIdentities::new(identities);

        let ops = vec![
            AdditiveOperation::Input {
                party_id: 0,
                output: WireId(0),
            },
            AdditiveOperation::Input {
                party_id: 1,
                output: WireId(1),
            },
            AdditiveOperation::Input {
                party_id: 2,
                output: WireId(2),
            },
            AdditiveOperation::Add {
                left: WireId(0),
                right: WireId(1),
                output: WireId(3),
            },
            AdditiveOperation::Add {
                left: WireId(3),
                right: WireId(2),
                output: WireId(4),
            },
            AdditiveOperation::Reveal {
                input: WireId(4),
                output: WireId(5),
            },
        ];

        let mut network_futures = Vec::new();
        #[allow(clippy::needless_range_loop)]
        for i in 0..n_parties {
            let sk = signing_keys[i].clone();
            let idents = node_identities.clone();
            network_futures.push(MeshNetwork::from_identities(i, sk, idents));
        }

        let networks = futures::future::try_join_all(network_futures)
            .await
            .unwrap();

        let mut exec_futures = Vec::new();

        for (i, network) in networks.into_iter().enumerate() {
            let ops_clone = ops.clone();
            let scheme_clone = scheme.clone();

            let exec_future = async move {
                let circuit = MpcCircuit::new(ops_clone, scheme_clone).unwrap();
                let config = MpcConfig::new(i, n_parties, circuit).unwrap();
                let mut exec = ExecutionContext::new(config, network).unwrap();

                exec.handshake().await.unwrap();
                exec.do_offline().await.unwrap();

                let input_val = (i as u64 + 1) * 10; // 10, 20, 30
                let input_wire = WireId(i);
                exec.prepare_input(vec![(input_wire, input_val)]).unwrap();

                exec.do_online().await.unwrap();

                let mut final_result = None;
                exec.dump_wires_with_filter(|w| {
                    if *w == 60 {
                        final_result = Some(*w);
                    }
                    true
                });

                assert_eq!(
                    final_result,
                    Some(60),
                    "Party {} failed to compute correct sum",
                    i
                );
                Ok::<(), snafu::Whatever>(())
            };
            exec_futures.push(exec_future);
        }

        futures::future::try_join_all(exec_futures).await.unwrap();
    }
}
