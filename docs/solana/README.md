# Solana Setup

This project is scaffolded for future Anchor programs and MagicBlock local testing.

- `Anchor.toml` pins the Anchor/Solana toolchain and clones MagicBlock's delegation and permission programs into the local validator.
- `Cargo.toml` defines an empty Rust workspace that will pick up future Anchor programs under `programs/*`.
- `src/lib/magicblock` contains shared MagicBlock RPC constants and a small client connection helper.
- `docs/solana/localnet-testing.md` documents the local validator flow.

No on-chain programs are included yet.
