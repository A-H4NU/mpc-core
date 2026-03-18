use core::error::Error;
use core::fmt::Debug;
use core::marker::Send;

use super::WireId;
use crate::{
    mpc::MpcCircuit,
    networking::{Network, ReceiveRequest, SendRequest},
};
use serde::{Deserialize, Serialize};

/// A type that represents an MPC operation.
///
/// An implementation must satisfy the following invariant:
///
/// ```rust,ignore
/// // Any "input" operation must yield exactly one output.
/// assert!(op.get_input_party_id().is_none() || op.outputs().count() == 1);
/// ```
pub trait Operation {
    /// If the operation is an input, return the id of the party that gives the input. Otherwise,
    /// return [`None`].
    fn get_input_party_id(&self) -> Option<usize>;

    /// Return the iterator of the input wires of this operation.
    fn inputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a>;

    /// Return the iterator of the output wires of this operation.
    fn outputs<'a>(&'a self) -> Box<dyn Iterator<Item = WireId> + 'a>;

    fn is_input(&self) -> bool {
        self.get_input_party_id().is_some()
    }
}

pub struct NetworkPhaseOutput<'a, S: MpcScheme> {
    pub pending: S::Pending<'a>,
    pub send_request: Vec<SendRequest<'a, S::NetworkElement>>,
    pub receive_request: Vec<ReceiveRequest<S::NetworkElement>>,
}

#[repr(transparent)]
pub struct FinalizePhaseOutput<S: MpcScheme>(pub Vec<S::Wire>);

/// A type that represents an MPC scheme.
pub trait MpcScheme
where
    Self: Debug + Clone + Serialize + for<'de> Deserialize<'de>,
{
    /// The context type that contains the necessary information that should be remembered during
    /// the entire execution. See [`MpcScheme::establish_context`],
    /// [`MpcScheme::do_network_phase`], and [`MpcScheme::do_finalize_phase`].
    type Context: Debug;

    /// The type that represents the element that travels across the network.
    type NetworkElement: Debug + Serialize + for<'de> Deserialize<'de>;

    /// The type that represents the wire value.
    type Wire: Debug;

    /// The type that represents the input from the party.
    type Input: Debug;

    /// The type that represents the operation.
    type Operation: Debug + Serialize + for<'de> Deserialize<'de> + Operation;

    /// The type that represents the pending operation returned from [`MpcScheme::do_network_phase`]
    /// and consumed by [`MpcScheme::do_finalize_phase`].
    type Pending<'a>: Debug;

    /// The error type returned by [`MpcScheme::establish_context`].
    type EstablishContextError: Error + Send + Sync + 'static;
    /// The error type returned by [`MpcScheme::do_network_phase`].
    type NetworkPhaseError: Error + Send + Sync + 'static;
    /// The error type returned by [`MpcScheme::do_finalize_phase`].
    type FinalizePhaseError: Error + Send + Sync + 'static;

    /// Returns true if the circuit "makes sense". [`MpcCircuit::new`] will fail if this returns
    /// false.
    ///
    /// * `circuit`: an iterator of operations
    fn is_circuit_sound<'a, I>(&self, circuit: I) -> bool
    where
        Self::Operation: 'a,
        I: IntoIterator<Item = &'a Self::Operation>;

    /// Returns `true` if `op` can be done without communication whenever the inputs are ready.
    ///
    /// ```rust,ignore
    /// // The "input" operation of this scheme must not be local.
    /// assert!(!op.is_input() || !scheme.is_operation_local(op));
    /// ```
    ///
    /// * `op`: The operation.
    fn is_operation_local(&self, op: &Self::Operation) -> bool;

    /// Specify how the context should be established given a network and the circuit.
    fn establish_context<N: Network>(
        &self,
        network: &mut N,
        circuit: &MpcCircuit<Self>,
    ) -> Result<Self::Context, Self::EstablishContextError>;

    /// The caller should ensure that the inputs are valid.
    fn prepare_user_input<I>(&self, context: &mut Self::Context, inputs: I)
    where
        I: IntoIterator<Item = (WireId, Self::Input)>;

    /// Given a context, an operation, and the inputs, return the send/receive requests that should
    /// be processed before calling the corresponding [`MpcScheme::do_network_phase`]. This
    /// function must sanitize `inputs`.
    fn do_network_phase<'a, I>(
        &self,
        context: &mut Self::Context,
        op: &Self::Operation,
        inputs: I,
    ) -> Result<NetworkPhaseOutput<'a, Self>, Self::NetworkPhaseError>
    where
        Self::Wire: 'a,
        I: IntoIterator<Item = &'a Self::Wire>;

    /// Given a context, a pending operation, and the (possible) network data, finalize the
    /// operation and return the corresponding outputs. The return value must be consistent with
    /// [`Operation::outputs`] (i.e. the number of output wires must match).
    fn do_finalize_phase<'a, I>(
        &self,
        context: &mut Self::Context,
        pending: Self::Pending<'a>,
        network_data: I,
    ) -> Result<FinalizePhaseOutput<Self>, Self::FinalizePhaseError>
    where
        I: IntoIterator<Item = Self::NetworkElement>;
}
