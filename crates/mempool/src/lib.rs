#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_doc_comments)]
#![allow(ambiguous_glob_reexports)]
#![allow(unexpected_cfgs)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::panicking_unwrap)]
#![allow(non_camel_case_types)]
//! Aethelred mempool crate.
//!
//! Provides transaction validation and middleware primitives.

pub mod middleware;
