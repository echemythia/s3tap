//! Offline harness: replay S3 access traces through a cache simulator and a
//! ladder of predictors to measure how predictable the workload is.
//!
//! Pure userspace — no eBPF, no kernel, no real object bytes. The simulator
//! models residency only.
//!
//! NOTE: `pub mod` lines are added incrementally — each module-creating task
//! below appends its own declaration. Declaring modules whose files don't exist
//! yet would fail to compile every commit (and break the whole workspace, since
//! this crate is a member), exactly as the root Cargo.toml warns about crates.

pub mod env;
pub mod trace;
pub mod rng;
pub mod synth;
pub mod sim;
pub mod predict;
pub mod metrics;
pub mod driver;
pub mod bytes;
pub mod adapt;
pub mod ibm;
pub mod admission;
pub mod hybrid;
pub mod link;
pub mod arc;
pub mod s3fifo;
