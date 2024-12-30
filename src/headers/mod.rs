//! Proxy headers management.

pub mod forward;
pub mod hopby;
pub mod via;

pub use forward::{
    ForwardedHeaderConfig, ForwardeeMode, SetForwardedHeader, SetForwardedHeaderLayer,
};
pub use hopby::{StripHopByHop, StripHopByHopLayer};
pub use via::{SetViaHeader, SetViaHeaderLayer, ViaHeaderMode};
