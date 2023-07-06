# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2023-07-06

- Upgrade `blind-rsa-signatures` to `0.15.0`.
- Derive additional traits on commonly used types.

## [2.0.0] - 2023-05-25

- Add new feature flags that control which TLS implementation and cert store is used.
- Remove the `client` feature (always present now, cannot be turned off).
- Streamline the public API by giving well-defined types to concepts such as `PoolId`.
- Upgrade `rust-bitcoin` to `0.30.0`.
- Upgrade other dependencies.
- Update `README.md`.
- Fix a recursion problem in `Display` implementations for two error types.
- Fix clippy warnings.
- Start tracking changes in this changelog.
- Start signing commits and releases.

