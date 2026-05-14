# rust-supervisor-relay

`rust-supervisor-relay` is a standalone relay server for the supervisor dashboard. It stays in `~/rust-supervisor-relay` and does not write implementation files into `~/rust-supervisor` or `~/rust-supervisor-ui`.

The Chinese README is available at [README.zh.md](README.zh.md).

## Scope

This package implements `DashboardRelayConfig`, target process dynamic registration, active registration tracking, `TargetProcessRegistry`, mTLS identity derivation, trusted proxy validation, `wss://` entrypoint validation, and the TLS listener startup skeleton.

The relay connects to target IPC only after an authenticated client session has been established and bound to a target. After binding, it reads target state, creates event and log subscriptions, and allows command forwarding.

The first target IPC implementation uses Unix domain sockets with newline-delimited JSON. `UnixNdjsonIpcClient` is the production implementation of `TargetIpcPort`. Tests drive real socket request and response flows through temporary `UnixListener` instances.

## Configuration

Example configuration is available at `examples/config/dashboard-relay.yaml`.

`listen.public_url` must use `wss://`. `registration.allowed_ipc_path_prefixes` must not be empty. A target process registration must report an absolute IPC path under one of the allowed prefixes.

Relay configuration does not accept a static target list. All targets must enter the registry through dynamic registration.

## Run

```bash
cargo run --manifest-path ~/rust-supervisor-relay/Cargo.toml -- --config ~/rust-supervisor-relay/examples/config/dashboard-relay.yaml --check
```

`--check` validates only the YAML structure and security policy. Without `--check`, the binary binds the registration socket and the `wss://` TCP listener, then waits for shutdown.

Real runtime usage requires `tls.certificate_path`, `tls.private_key_path`, and `tls.client_ca_path` to point to valid certificate files.

## Install

After the package is published to crates.io, install the relay binary with:

```bash
cargo install rust-supervisor-relay
```

Then run:

```bash
rust-supervisor-relay --config /path/to/dashboard-relay.yaml --check
```

## Verify

```bash
cargo fmt --manifest-path ~/rust-supervisor-relay/Cargo.toml
cargo test --manifest-path ~/rust-supervisor-relay/Cargo.toml
```

The tests cover registration configuration, duplicate target IDs, duplicate IPC paths, invalid leases, full-control rejection over `ws://`, trusted proxy identity spoofing rejection, session gating, event and log binding order, sequence gaps, reconnect timeouts, command `requested_by` derivation, dangerous command confirmation, and command audit recording.
