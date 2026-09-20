# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/KarpelesLab/spotlib-rs/compare/spotlib-v0.1.1...spotlib-v0.1.2) - 2026-09-20

### Fixed

- *(wasm)* adapt the browser client to rsurl 0.1.15's WebSocket API

## [0.1.1](https://github.com/KarpelesLab/spotlib-rs/compare/spotlib-v0.1.0...spotlib-v0.1.1) - 2026-07-23

### Added

- support wasm32 (browser) via async implementation behind a feature flag

### Fixed

- fix peer reconnection so host changes trigger a fresh host pull

### Other

- wait for min_conn connections, not just one
- apply rustfmt across the workspace
