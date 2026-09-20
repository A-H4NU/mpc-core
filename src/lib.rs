//! Multipaty computation core protocol logic and primitive types.
//!
//! Provides the primary primitives for establishing network channels, defining and validating
//! topological arithmetic and boolean circuits, and executing operations under secure evaluation
//! conditions.

/// Contains concrete scheme implementations used for developmental reference.
pub mod example;
/// Implements the fundamental algebraic evaluation pipelines and state machines for computation
/// phases.
pub mod mpc;
/// Encompasses transport primitives for executing network communications between nodes securely.
pub mod networking;
