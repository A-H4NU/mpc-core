# mpc-core

> A flexible, trait-based core framework and asynchronous execution engine for Multi-Party Computation (MPC) protocols.

`mpc-core` provides the foundational building blocks required to design,
compile, and execute secure multi-party computation protocols. By strictly
decoupling the **cryptographic scheme**, the **circuit representation**, and the
**network transport**, this crate allows researchers and engineers to build
custom MPC protocols without having to rewrite complex asynchronous state
machines or graph evaluation logic.

## Core Architecture

The crate is built around a few central abstractions:

### 1. `MpcScheme`

The `MpcScheme` trait defines the mathematical and cryptographic rules of your
protocol. You define the types for your `Wire`s, `Input`s, and
`NetworkElement`s, as well as an `Operation` enum representing the gates of your
circuit (e.g., `Add`, `Multiply`, `Reveal`).

The scheme dictates which operations can be computed locally and which require
network communication (`do_network_phase` and `do_finalize_phase`).

### 2. `MpcCircuit`

Circuits are constructed as Directed Acyclic Graphs (DAGs) of operations. When
you instantiate an `MpcCircuit`, the engine uses Kahn's algorithm to perform
topological sorting. It strictly validates the circuit to ensure:

- There are no cycles.
- No wire is produced more than once.
- No wire is consumed before it is produced.

It then organizes the operations into structured **Offline** and **Online**
"waves," separating local computations from network-bound gates to optimize
asynchronous execution.

### 3. `Network`

A generic `Network` trait abstracts the underlying transport layer. It provides
asynchronous primitives for point-to-peer and broadcast messaging. It relies on
the highly efficient `postcard` format for zero-cost, strongly-typed object
serialization over the wire.

You can plug in your own networking backend, whether it's local in-memory
channels for testing, WebRTC, or raw TCP sockets.

### 4. `ExecutionContext`

The `ExecutionContext` is a state-machine-driven engine that actually executes
the compiled `MpcCircuit`. It safely manages the transition between states
(`NewBorn` -> `Handshaked` -> `FinishedOffline` -> `ReadyOnline` -> `Finished`),
handling all concurrent network I/O in efficient, bulk batches to prevent
network fragmentation.

## Features

- **High-Performance Async:** Built from the ground up to support Rust's
  `Future`s. The execution engine evaluates local gates immediately and batches
  network requests concurrently.
- **Modular:** Swap out your secret-sharing scheme (Additive, Shamir, BGW, etc.)
  without touching the network code, or swap your network without touching the
  cryptography.
- **Type-Safe:** Heavily utilizes Rust's type system (GATs, const generics) to
  ensure that wire types and network elements remain strictly checked at compile
  time.

## Included Examples

This crate includes robust example implementations behind feature flags to help
you get started:

- **`example-additive`**: A complete implementation of an additive secret
  sharing scheme over a generic ring modulo $M$. It implements operations like
  `Input`, `GenRandom`, `Add`, and `Reveal`.
- **`example-secure-network`**: A peer-to-peer secure TCP mesh network
  implementation powered by `tokio`. It features an authenticated handshake
  using Ephemeral Diffie-Hellman (`x25519-dalek`), Ed25519 signatures, and
  ChaCha20Poly1305 AEAD encryption for secure stream transport.

### Running the Examples

You can run the integration tests that combine the additive scheme and the
secure mesh network:

```bash
cargo test --features "example-additive,example-secure-network"
```

## Usage

Add `mpc-core` to your `Cargo.toml`:

```toml
[dependencies]
mpc-core = "0.1.0"
```

*Note: This crate relies on advanced Rust features and requires Rust edition
2024 or later.*

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
