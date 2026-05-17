# Solana Setup

This project is scaffolded for Anchor programs, Light Protocol compressed PDA testing, and MagicBlock local testing.

- `Anchor.toml` pins the Anchor/Solana toolchain and clones MagicBlock's delegation and permission programs into the local validator.
- `Cargo.toml` defines the Rust workspace and picks up programs under `programs/*`.
- `programs/passkey-registry` stores passkey authority records in Light Protocol compressed PDAs.
- `src/lib/magicblock` contains shared MagicBlock RPC constants and a small client connection helper.
- `docs/passkey-registry-architecture.md` documents the passkey compressed PDA design.
- `docs/solana/localnet-testing.md` documents the local validator flow.
