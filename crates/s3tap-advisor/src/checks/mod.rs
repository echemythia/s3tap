//! The advisory checks, one module per task. Each exposes a single
//! `check_*(records) -> Vec<Finding>` registered in `advise()`.

pub(crate) mod churn;
pub(crate) mod parallelism;
pub(crate) mod refetch;
pub(crate) mod patterns;
pub(crate) mod service;
pub(crate) mod caching;
