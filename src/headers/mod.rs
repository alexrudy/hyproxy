//! Proxy headers management.
//!
//! The middleware most proxies need is re-exported here:
//!
//! - [`SetForwardedHeaderLayer`]: add a `Forwarded` (and optionally `X-Forwarded-*`) header
//!   describing this hop. See [`forward`].
//! - [`SetViaHeaderLayer`]: add a `Via` header to requests and responses. See [`via`].
//! - [`StripHopByHopLayer`]: remove hop-by-hop headers, which must not be forwarded.
//!   See [`hopby`].
//!
//! The [`chain`] and [`fields`] modules provide the typed parsing these are built on, for
//! headers which can have multiple comma-separated values, and multiple lines.

pub mod chain;
pub mod connection;
pub mod fields;
pub mod forward;
pub mod hopby;
pub(crate) mod parser;
pub mod via;

pub use forward::{
    ForwardedHeaderConfig, ForwardeeMode, SetForwardedHeader, SetForwardedHeaderLayer,
};
pub use hopby::{ConnectionHeaders, StripHopByHop, StripHopByHopLayer};
pub use via::{SetViaHeader, SetViaHeaderLayer};
