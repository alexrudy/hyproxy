Proxy utilities for hyper-based services.

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT licensed][license-image]

This crate provides primitives specific to building proxies and reverse proxies with `hyper`,
as `tower` middleware over `http` types:

- `Forwarded` (RFC 7239) and `X-Forwarded-*` headers, with typed parsing and configurable
  handling of values from upstream proxies.
- `Via` headers, and stripping of hop-by-hop headers.
- Rewriting request URIs, responding early from middleware, and proxying HTTP upgrades
  (with the `upgrade` feature).

The optional `hyperdriver` feature integrates with
[`hyperdriver`](https://crates.io/crates/hyperdriver) connection info.

See the [documentation][docs-link] for details.

[crate-image]: https://img.shields.io/crates/v/hyproxy
[crate-link]: https://crates.io/crates/hyproxy
[docs-image]: https://docs.rs/hyproxy/badge.svg
[docs-link]: https://docs.rs/hyproxy/
[build-image]: https://github.com/alexrudy/hyproxy/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/alexrudy/hyproxy/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
