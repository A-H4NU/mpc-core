use serde::{Deserialize, Serialize};
use snafu::Whatever;

use crate::{mpc::circuit::MpcCircuit, mpc::scheme::MpcScheme};

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "S: MpcScheme")]
pub struct MpcConfig<S: MpcScheme> {
    my_id: usize,
    n_parties: usize,
    circuit: MpcCircuit<S>,
}

impl<S: MpcScheme> MpcConfig<S> {
    pub fn new(my_id: usize, n_parties: usize, circuit: MpcCircuit<S>) -> Result<Self, Whatever> {
        if my_id >= n_parties {
            snafu::whatever!("`my_id` must be less than `n_parties`")
        }
        Ok(Self {
            my_id,
            n_parties,
            circuit,
        })
    }

    pub fn my_id(&self) -> usize {
        self.my_id
    }

    pub fn circuit(&self) -> &MpcCircuit<S> {
        &self.circuit
    }

    pub fn scheme(&self) -> &S {
        self.circuit.scheme()
    }

    pub fn n_parties(&self) -> usize {
        self.n_parties
    }
}
