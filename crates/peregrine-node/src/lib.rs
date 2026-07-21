//! # peregrine-node
//!
//! Wires the planes together into a runnable validator and provides the
//! in-process multi-validator simulation used by `peregrine-sim`.
//!
//! Module map:
//! * [`network`] — in-process reliable broadcast standing in for the
//!   QUIC/Turbine fan-out layer. Same trait-shaped surface we will point at
//!   real sockets.
//! * [`payload`] — the wire encoding of what rides inside consensus
//!   vertices (stream shreds, Talon transactions).
//! * [`pipeline`] — the execution/data pipeline: consumes the committed
//!   total order, applies shreds to the [`StreamRegistry`], materializes
//!   stream ticks into a [`TableStore`] table (the first "materialized
//!   view"), runs Talon programs, and settles dual-meter fees.
//! * [`validator`] — the per-node event loop: receive vertices, extend the
//!   DAG, propose, commit.
//! * [`store`] — node-owned crash-durable persistence (redb): snapshot and
//!   restore the DAG and materialized table state so a node survives restarts.
//! * [`rpc`] — the client-facing QUIC endpoint: serves the `peregrine-sdk`
//!   protocol (publish, submit tx, proven read, store root).
//! * [`devnet`] — one-call local node + RPC listener for SDK examples/tests.

pub mod bench;
pub mod demos;
pub mod devnet;
pub mod network;
pub mod payload;
pub mod pipeline;
pub mod quic;
pub mod rpc;
pub mod rpc_limits;
pub mod sim;
pub mod store;
pub mod tiles;
pub mod validator;
