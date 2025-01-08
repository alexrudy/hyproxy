//! Proxy headers management.

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
pub use hopby::{StripHopByHop, StripHopByHopLayer};
pub use via::{SetViaHeader, SetViaHeaderLayer};
