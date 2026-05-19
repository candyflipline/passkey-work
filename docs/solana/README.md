# Solana Setup

This project is scaffolded for Anchor programs, Light Protocol compressed PDA testing, and MagicBlock local testing.

`Anchor.toml` pins the Anchor/Solana toolchain and clones MagicBlock's delegation and permission programs into the local validator. `Cargo.toml` defines the Rust workspace and picks up programs under `programs/*`.

The active program is `programs/passkey-registry`. It stores passkey and wallet authority records in Light Protocol compressed PDAs, shares one pooled Squads verifier path across both authority types, and keeps local SBF tests close to the production account model. `src/lib/magicblock` contains shared MagicBlock RPC constants and a small client connection helper.

For details, read `docs/passkey-registry-architecture.md` for the compressed PDA design and `docs/solana/localnet-testing.md` for the local validator flow.
