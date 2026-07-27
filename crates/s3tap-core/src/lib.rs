// crates/s3tap-core/src/lib.rs
//
// The correlation layer: turns the raw EVT_* event stream into public
// s3tap.operation records. Pure logic, no kernel dependency.

mod correlate;
pub mod hash;
pub mod http;

pub use correlate::Correlator;
