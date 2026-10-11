# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.0](https://github.com/alexrudy/hyproxy/compare/v0.12.0...v0.13.0) - 2026-10-11

### Other

- API consistency fixes
- Tidy up Via handling
- Fixes for ProxyUpgrade handling
- Improved strip hop-by-hop
- Update documentation
- Additional helper methods
- Make API consistent
- Harden support for appending our own forwarding information, and extract
- Support for obfuscated ports in header values.
- Harden Forwarded header parsing
- Fix for values in headers: they should be quoted.
- Fix tokio dependency
- Unlock dependencies
- Improve dependency connections.
- Dynamically detect MSRV in CI
- Bump MSRV
- Upgrade all the dependencies.
- *(deps)* bump hyper from 1.11.0 to 1.11.1
- *(deps)* bump thiserror from 2.0.19 to 2.0.20
- *(deps)* bump http from 1.4.2 to 1.5.0
- *(deps)* bump hyper from 1.10.1 to 1.11.0
- Merge pull request #57 from alexrudy/dependabot/cargo/bytes-1.12.1
- *(deps)* bump thiserror from 2.0.18 to 2.0.19
- *(deps)* bump bytes from 1.12.0 to 1.12.1
- Merge pull request #49 from alexrudy/dependabot/cargo/hyper-1.10.1
- Merge pull request #53 from alexrudy/dependabot/cargo/bytes-1.12.0
- Merge pull request #54 from alexrudy/dependabot/cargo/chateau-0.3.2
- Merge pull request #55 from alexrudy/dependabot/cargo/http-1.4.2
- *(deps)* bump hyperdriver from 0.12.3 to 0.12.4
- *(deps)* bump http from 1.4.0 to 1.4.2
- *(deps)* bump chateau from 0.3.1 to 0.3.2
- *(deps)* bump bytes from 1.11.1 to 1.12.0
- *(deps)* bump hyper from 1.8.1 to 1.10.1
- Merge pull request #51 from alexrudy/dependabot/cargo/bytes-1.11.1
- Merge pull request #50 from alexrudy/dependabot/cargo/tokio-1.50.0
- Merge pull request #48 from alexrudy/dependabot/cargo/pin-project-lite-0.2.17
- *(deps)* bump bytes from 1.11.0 to 1.11.1
- *(deps)* bump pin-project-lite from 0.2.16 to 0.2.17

### Fixed

- `ProxyUriService` no longer panics on origin-form requests (`GET /path`) when no authority is
  configured. It now falls back to the `Host` header for the authority, and leaves the URI
  unchanged if there is no authority, or no path (as for `CONNECT` requests).
- `ProxyUpgrade` now detects upgrade requests from browsers, which send `Connection: Upgrade`
  (capitalised). `Connection` options are compared case-insensitively, as RFC 9110 requires, and
  every `Connection` and `Upgrade` header line is read.
- `Via` headers with a comment (e.g. `1.1 varnish (Varnish/6.0)`, as sent by Apache and Varnish)
  now parse, and the comment is preserved when the header is re-serialized. Nesting is limited
  to 16 levels.
- `ViaProtocol::from(http::Version)` no longer panics on unrecognised versions.
- `StripHopByHop` now reads every `Connection` header line. Previously only the first was used,
  so headers named on later lines were forwarded.
- `StripHopByHop` now removes `Keep-Alive`, `Proxy-Connection` and `Upgrade` even when
  `Connection` does not name them, per RFC 9110 section 7.6.1.
- `StripHopByHop` no longer removes `Trailer`, which is an end-to-end header announcing the
  fields in the trailer section.
- `Connection` header parsing now accepts empty list elements (`a, , b`), and
  `ConnectionHeader`'s `HeaderRecordKind::into_bytes` no longer panics.
- `Forwarded` header values that are not valid tokens are now quoted, as required by RFC 7239.
  Previously, IPv4 addresses with a port (`for=192.0.2.1:8080`), hosts with a port
  (`host=example.com:8080`) and IPv6 hosts were emitted unquoted, producing headers that
  downstream servers (and hyproxy itself) could not parse.
- Quoted extension values in an incoming `Forwarded` header (e.g. `ext="a, b"`) are no longer
  stripped of their quotes when the header chain is re-serialized.
- `ForwardedRecord::any` now returns `true` for non-empty unparsed (raw) records; the check was inverted.
- `fields::combine_values` preserves quotes on quoted-string values, so its output round-trips
  through `fields::parse_header`.
- Quoted obfuscated identifiers (e.g. `for="_gazonk"`, the example from RFC 7239 section 4)
  are now parsed as obfuscated nodes.
- `unknown` is now matched case-insensitively in `for`/`by`.
- Escape sequences in quoted `for`, `by`, `host` and `proto` values are now decoded before
  the value is interpreted.
- Empty pairs (`for=a;;proto=http`) and empty list elements (`for=a,,for=b`) in a `Forwarded`
  header are now accepted and ignored.
- `ForwardAddress` parsing is stricter, per RFC 7239 section 6: trailing data after an IPv6
  address (`[::1]junk`), unbracketed IPv6 addresses, bracketed IPv4 addresses, and ports that
  are not 1 to 5 digits (e.g. `+80`) are now rejected. Quoted IPv4 addresses with a port
  (`"192.0.2.1:8080"`) now parse correctly.
- `for` and `by` nodes now support the full RFC 7239 section 6 grammar, including obfuscated
  ports (`"[2001:db8::17]:_p0rt"`) and ports on `unknown` and obfuscated names
  (`"unknown:8080"`, `"_hidden:_port"`). Previously these caused the whole header value to be
  treated as an unparsed raw record.
- `Forwarded::new` (and so `SetForwardedHeader`) now falls back to the request URI's authority
  for `host` when there is no `Host` header, so `host` is populated for HTTP/2 requests.
- `X-Forwarded-Host` and `X-Forwarded-Proto` are no longer appended to existing values, which
  produced ambiguous multi-valued headers such as `X-Forwarded-Proto: https, http`.
- `Forwarded::any` now considers extension parameters, so a record with only extensions is no
  longer dropped by `Forwarded::set_header`.
- Corrected documentation: `X_FORWARDED_FOR` was described as `X-Forwarded-By`, and
  `ForwardedProtocol` cited "RFC-2739" and claimed only `http`/`https` are permitted.
- docs.rs now builds with all features enabled, so the `upgrade` module and
  `ConnectionInfoAdapter` appear in the published documentation.

### Changed

- **Breaking:** `StripHopByHop` now takes a `ConnectionHeaders` policy instead of a
  `preserve_connection` flag, adding `PreserveUpgrade`, which keeps only `Upgrade` and
  `Connection: upgrade` on upgrade requests and `101 Switching Protocols` responses. To migrate:
  - `StripHopByHopLayer::new(false)` → `StripHopByHopLayer::new()`
  - `StripHopByHopLayer::new(true)` →
    `StripHopByHopLayer::new().connection_headers(ConnectionHeaders::Preserve)`, or
    `ConnectionHeaders::PreserveUpgrade` to forward only upgrades.
  - `StripHopByHop::new(inner, preserve)` → `StripHopByHop::new(inner).connection_headers(..)`
- **Breaking:** `From<SocketAddr> for ViaAddress` is now `TryFrom<SocketAddr>`, as it panicked on
  IPv6 addresses, which are not valid `received-by` tokens under RFC 9110.
- `SetViaHeader` now omits the protocol name for HTTP (`1.1 proxy` rather than `HTTP/1.1 proxy`),
  as RFC 9110 section 7.6.3 recommends.
- **Breaking:** `UpgradeProtocol` equality is now an equivalence relation: a missing version no
  longer equals every version (previously `websocket/1 == websocket == websocket/2`, but
  `websocket/1 != websocket/2`). The lenient comparison is available as
  `UpgradeProtocol::matches`, which `UpgradeRequest::matching` uses, so upgrade matching is
  unchanged. `UpgradeProtocol` now implements `Eq`.
- **Breaking:** `SetViaHeader::request` and `SetViaHeader::response` are now builder methods taking
  an `AppendHeaderRecordMode`, matching `SetViaHeaderLayer`, rather than returning `&mut`. To
  migrate, replace `*service.request() = mode` with `service = service.request(mode)`.
- `BailService::service` is deprecated in favour of `BailService::inner`.
- `HeaderChain::append_record` no longer requires `T: Debug`, and the `(C, Request<B>)` service
  implementation of `ProxyUriService` no longer requires `B: Send + 'static`.
- `ParseViaError` messages are now consistently lower-case and mention the `Via` header.

- `ProxyUpgrade` logs unparseable client `Upgrade` headers and failed client upgrades at `debug`
  level, and failed upstream upgrades at `warn`, rather than `error`.
- The `ProxyUriLayer` and `ProxyUriService` documentation now states that the scheme always
  replaces the request's scheme, rather than only being set when missing.
- **Breaking:** `hopby::HOPBYHOP` no longer includes `Trailer`, and is now a `[HeaderName; 4]`.
- **Breaking:** removed `RemoveConnectionHeaders`, `RemoveConnectionHeadersLayer` and
  `RemoveConnectionHeadersConfig` from `headers::connection`, which duplicated `StripHopByHop`
  (and whose `preserve_if_upgrade`/`preserve_if_close` options could not be set). Use
  `StripHopByHop` with a `ConnectionHeaders` policy instead.
- **Breaking:** `Forwardee` is now a struct of a `NodeName` and an optional `NodePort`, rather
  than an enum, so that every kind of node can carry a port. To migrate:
  - `Forwardee::Address(addr)` → `Forwardee::address(addr)` (or `Forwardee::from(addr)`)
  - `Forwardee::Named(token)` → `Forwardee::obfuscated(ObfuscatedName::try_from(token)?)`
  - `Forwardee::Unknown` → `Forwardee::unknown()`
  - Matching on variants → `forwardee.name()` / `forwardee.port()`, or `forwardee.ip()` for
    the IP address.
- **Breaking:** `ForwardeeMode::Named(Token)` has been renamed to
  `ForwardeeMode::Obfuscated(ObfuscatedName)`, matching the RFC 7239 terminology and
  `NodeName::Obfuscated`. Names are now validated against the `obfnode` grammar when the
  `ObfuscatedName` is constructed, rather than producing an invalid header; use
  `ObfuscatedName::from_static("name")` (checked at compile time in a `const`) or
  `ObfuscatedName::try_from(token)` to migrate.
- **Breaking:** `ForwardedHost`'s `FromStr::Err` is now `ParseForwardedError` (was
  `http::uri::InvalidUri`). Host values containing userinfo (`user@example.com`) are now
  rejected rather than having the userinfo silently dropped, as the `Host` header grammar
  does not permit it.
- **Breaking:** methods which allocate a new header value or byte buffer now consistently use
  the `to_` prefix, per the Rust API guidelines:
  - `ForwardAddress::as_header_value` → `to_header_value`
  - `ForwardedProtocol::as_bytes` → `to_bytes`
  - `XForwardee::header_value` → `to_header_value`
  - `XForwardedHost::as_header_value` → `to_header_value`
  - `XForwardedProtocol::as_header_value` → `to_header_value`
- `ParseForwardedError` and `ForwardParseError` now forward `Error::source` to the underlying
  error (e.g. `http::uri::InvalidUri`), rather than hiding it. A `proto` value that is not a
  valid scheme now reports its `InvalidUri` as the source.
- `ConnectionInfoAdapter` now logs a missing `ConnectionInfo` at `debug` level rather than
  `warn`, as it is expected for some transports and would otherwise log on every request.
- `proto` in `Forwarded::new` now prefers the new `ConnectionScheme` request extension over the
  request URI's scheme, since the URI scheme describes the request target rather than the
  connection, and is absent for most HTTP/1.1 requests.
- `SetForwardedHeader` now applies its `AppendHeaderRecordMode` to existing `X-Forwarded-*`
  headers (when `set_x_headers` is enabled), so the X-headers follow the same trust policy as the
  `Forwarded` chain:
  - `Append`, `Chain`, `Flatten` and `Expand` add our address to `X-Forwarded-For` (combined as the
    mode describes), and keep any existing `X-Forwarded-Host`/`X-Forwarded-Proto`.
  - `KeepFirst` keeps only the first existing entry of each header, falling back to ours.
  - `KeepLast` replaces all existing values with ours (appropriate at the network edge).
  - `Omit` removes the `X-Forwarded-*` headers.
- `Forwarded::set_x_forwarded_headers` (and the chain-level `set_all_x_forwarded_headers`) now
  behave like the `Append` mode above: `X-Forwarded-Host`/`X-Forwarded-Proto` are only set if
  not already present.
- The `hyperdriver` feature now also enables an optional dependency on `chateau` (already a
  dependency of `hyperdriver`), to read TLS connection info.
- `ForwardAddress::from_str` now rejects nodes that are valid but cannot be represented as an IP
  address with a numeric port (e.g. `unknown`, `_hidden`, or an obfuscated port).
- `ForwardAddress::to_bytes`, `ForwardAddress::to_header_value` and `ForwardAddress`'s `Display`
  implementation now quote IPv4 addresses that include a port (`"192.0.2.1:8080"`).
- `Forwarded` parsing no longer accepts whitespace around `=` (`for = unknown`), which RFC 7239
  does not permit. Such headers are preserved as raw, unparsed records.
- Obfuscated identifiers (`_name`) must now contain at least one character after the `_`, and
  only `ALPHA / DIGIT / "." / "_" / "-"`, per the RFC 7239 `obfnode` grammar.

### Added

- `hopby::ConnectionHeaders` (also re-exported from `headers`), and the `hopby::CONNECTION_SCOPED`,
  `hopby::KEEP_ALIVE` and `hopby::PROXY_CONNECTION` constants.
- `StripHopByHop::{connection_headers, direction, inner, into_inner}` and
  `StripHopByHopLayer::{connection_headers, direction}`.
- `hopby::StripDirection`, to strip only requests or only responses. This allows one layer to
  be placed next to the client and another next to the upstream, so that neither can use
  `Connection` to remove headers added by the proxy. The default remains to strip both.
- `FieldValue::to_header_bytes`, which returns the value in its serialized header form,
  retaining the surrounding quotes for quoted strings.
- `FieldValue::unescaped` and `QuotedText::unescaped`, which return the value with
  `quoted-pair` escape sequences decoded.
- `ObfuscatedName`, a validated RFC 7239 obfuscated identifier (`obfnode` / `obfport`), used by
  `NodeName::Obfuscated`, `NodePort::Obfuscated` and `ForwardeeMode::Obfuscated`.
- `NodeName` and `NodePort` types, and `Forwardee::{new, address, obfuscated, unknown, name, port,
  ip, with_port, without_port}`.
- `FromStr` and `Display` for `Forwardee`, `NodeName` and `NodePort`.
- `Forwarded::append_x_forwarded_headers`, which sets the `X-Forwarded-*` headers according to an
  `AppendHeaderRecordMode`.
- `Forwarded::{with_by, with_for, with_host, with_proto, with_extension}` builder methods, since
  `Forwarded` is `#[non_exhaustive]` and cannot be constructed with a struct literal outside
  this crate.
- `SetForwardedHeader::{set_x_headers, append_forwarded_headers, inner, into_inner}`, matching
  the configuration available on `SetForwardedHeaderLayer`.
- `ForwardedProtocol::{scheme, into_scheme}` and `From<ForwardedProtocol> for http::uri::Scheme`.
- `X_FORWARDED_PORT` header name constant.
- `HeaderChain::try_from_headers`, a strict alternative to `from_headers` which returns an error
  rather than preserving unparseable header values as raw records.
- `HeaderChain::{first_record, last_record}`, which return the first or last record across all
  header lines in the chain, skipping empty lines.
- `Via::{new, with_comment, protocol, address, comment, to_bytes}`, `Display for Via`, and
  `ViaProtocol::{new, name, version}`, so `Via` entries can be built and inspected.
- `UpgradeProtocol::matches`.
- `inner` and `into_inner` on `BailService`, `SetViaHeader` and `ProxyUriService`, matching the
  other middleware.
- `upgrade` module documentation covering its requirements: a Tokio runtime, hyper on both
  sides, and `ConnectionHeaders::PreserveUpgrade` when used with `StripHopByHop`.
- `ConnectionScheme` request extension, used for the `proto` field of the `Forwarded` header.
  `ConnectionInfoAdapter` inserts `ConnectionScheme(https)` when TLS connection info is present.

## [0.12.0](https://github.com/alexrudy/hyproxy/compare/v0.11.2...v0.12.0) - 2026-06-05

### Other

- *(deps)* bump tracing from 0.1.43 to 0.1.44
- Merge pull request #42 from alexrudy/dependabot/cargo/tokio-1.49.0
- Merge pull request #43 from alexrudy/dependabot/cargo/tower-0.5.3
- Merge pull request #44 from alexrudy/dependabot/cargo/thiserror-2.0.18
- *(deps)* bump chateau from 0.2.1 to 0.3.1
- bump MSRV to support hypderdriver upgrade
- *(deps)* changes required to support hyperdriver 0.12.1
- *(deps)* bump hyperdriver from 0.11.0 to 0.12.1
- Merge pull request #38 from alexrudy/dependabot/cargo/bytes-1.11.0
- *(deps)* bump http from 1.3.1 to 1.4.0
- Merge pull request #35 from alexrudy/dependabot/cargo/tracing-0.1.43
- *(deps)* bump tokio from 1.45.1 to 1.48.0
- *(deps)* bump hyper from 1.6.0 to 1.8.1
- Update dependabot config

## [0.11.2](https://github.com/alexrudy/hyproxy/compare/v0.11.1...v0.11.2) - 2025-12-09

### Other

- X-Forwarded-For should not contain port numbers, only IP addresses.
