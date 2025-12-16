# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.3](https://github.com/alexrudy/hyproxy/compare/v0.11.2...v0.11.3) - 2025-12-16

### Other

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
