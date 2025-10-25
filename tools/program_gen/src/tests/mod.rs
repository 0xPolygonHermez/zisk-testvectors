mod arith_eq;
mod builder;
mod config;

pub(crate) use arith_eq::generate_arith_eq_tests;
pub(crate) use builder::*;
pub(crate) use config::*;

pub(crate) const MINIMAL_TESTS: usize = 5;
