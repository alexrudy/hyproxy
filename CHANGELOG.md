# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
  are now parsed as `Forwardee::Named`.
- `unknown` is now matched case-insensitively in `for`/`by`.
- Escape sequences in quoted `for`, `by`, `host` and `proto` values are now decoded before
  the value is interpreted.
- Empty pairs (`for=a;;proto=http`) and empty list elements (`for=a,,for=b`) in a `Forwarded`
  header are now accepted and ignored.
- `ForwardAddress` parsing is stricter, per RFC 7239 section 6: trailing data after an IPv6
  address (`[::1]junk`), unbracketed IPv6 addresses, bracketed IPv4 addresses, and ports that
  are not 1 to 5 digits (e.g. `+80`) are now rejected. Quoted IPv4 addresses with a port
  (`"192.0.2.1:8080"`) now parse correctly.

### Changed

- `ForwardAddress::to_bytes`, `ForwardAddress::as_header_value` and `ForwardAddress`'s `Display`
  implementation now quote IPv4 addresses that include a port (`"192.0.2.1:8080"`).
- `Forwarded` parsing no longer accepts whitespace around `=` (`for = unknown`), which RFC 7239
  does not permit. Such headers are preserved as raw, unparsed records.
- Obfuscated identifiers (`_name`) must now contain at least one character after the `_`, and
  only `ALPHA / DIGIT / "." / "_" / "-"`, per the RFC 7239 `obfnode` grammar.

### Added

- `FieldValue::to_header_bytes`, which returns the value in its serialized header form,
  retaining the surrounding quotes for quoted strings.
- `FieldValue::unescaped` and `QuotedText::unescaped`, which return the value with
  `quoted-pair` escape sequences decoded.

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
