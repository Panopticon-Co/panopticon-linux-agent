//! Security-sensitive primitives for the Panopticon Linux endpoint agent.
//! No API in this crate accepts a shell string or arbitrary executable path.
pub mod config;
pub mod identity;
pub mod queue;
pub mod response;
pub mod spool;
pub mod telemetry;
