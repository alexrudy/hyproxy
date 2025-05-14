# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/alexrudy/hyproxy/compare/v0.1.0...v0.2.0) - 2025-05-14

### Added

- Improve Forwarded support with value parsers
- nom parser for header values
- HeaderChain support
- Support extensions in FORWARDED header

### Fixed

- Update forwarding parsing

### Other

- *(deps)* bump pin-project-lite from 0.2.15 to 0.2.16
- Merge pull request #8 from alexrudy/dependabot/cargo/thiserror-2.0.12
- Merge pull request #7 from alexrudy/dependabot/cargo/hyper-1.6.0
- *(deps)* bump tokio from 1.42.0 to 1.44.2
- Layer to handle removing connection headers
- nom parsing for headers
- simplify chain impl
- Improve protocol handling
