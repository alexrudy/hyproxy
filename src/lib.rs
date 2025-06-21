//! # HyProxy
//!
//! `hyproxy` is a library for building HTTP proxies in Rust based on the `hyper` library.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![deny(unsafe_code)]

pub mod bail;
pub mod headers;
pub mod upgrade;
pub mod uri;
