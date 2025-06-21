# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/alexrudy/hyproxy/compare/v0.1.0...v0.2.0) - 2025-06-21

### Added

- Improve Forwarded support with value parsers
- nom parser for header values
- HeaderChain support
- Support extensions in FORWARDED header

### Fixed

- Update forwarding parsing

### Other

- [chore] update hyperdriver
- Bump MSRV for Waker::noop support
- Merge pull request #16 from alexrudy/dependabot/cargo/bytes-1.10.1
- Merge pull request #17 from alexrudy/dependabot/cargo/http-1.3.1
- Merge pull request #13 from alexrudy/feature/bail
- [chore] rename bailout -> bail in tests
- [chore] update test names for bail
- [chore] bump MSRV for compatiblity in tests
- [feat] Adds BailService
- Layer to handle removing connection headers
- nom parsing for headers
- simplify chain impl
- Improve protocol handling
