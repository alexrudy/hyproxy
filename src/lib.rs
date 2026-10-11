//! # HyProxy
//!
//! `hyproxy` provides building blocks for HTTP proxies and reverse proxies, as
//! [`tower`](https://docs.rs/tower) middleware over [`http`](https://docs.rs/http)
//! types, for use with [`hyper`](https://docs.rs/hyper).
//!
//! ## Modules
//!
//! - [`headers`]: proxy-related headers.
//!   - [`headers::forward`]: the `Forwarded` header (RFC 7239) and the `X-Forwarded-*` headers.
//!   - [`headers::via`]: the `Via` header.
//!   - [`headers::hopby`]: stripping hop-by-hop headers before forwarding.
//!   - [`headers::chain`], [`headers::fields`]: typed parsing of multi-valued header fields.
//! - [`uri`]: setting the scheme and authority of request URIs before forwarding.
//! - [`bail`]: middleware which can respond early, without calling the inner service.
//! - `upgrade` (with the `upgrade` feature): proxying HTTP upgrades, such as WebSockets.
//!
//! ## Feature flags
//!
//! - `hyperdriver`: integration with [`hyperdriver`](https://docs.rs/hyperdriver).
//!   This provides `ConnectionInfoAdapter` in [`headers::forward`], which supplies the
//!   connection addresses and scheme used for the `Forwarded` header.
//! - `upgrade`: the `upgrade` module.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![deny(unsafe_code)]

pub mod bail;
#[cfg(all(not(feature = "hyperdriver"), feature = "upgrade"))]
mod bridge;
pub mod headers;

#[cfg(feature = "upgrade")]
pub mod upgrade;
pub mod uri;
