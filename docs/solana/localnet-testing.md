# Localnet Testing

This project has two local paths:

- `bun run test:sbf` for the Light compressed PDA and Squads smart-account program tests.
- The MagicBlock local validator flow for future ephemeral-rollup integration tests.

## Main Program Gate

Run the registry SBF suite with:

```bash
bun run test:sbf
```

The suite uses `light-program-test`, starts the Light local environment and prover, loads `programs/passkey-registry`, and runs the compressed PDA registration plus Squads synchronous execution path.

The Squads E2E case also loads the Squads smart-account program. It expects a compiled `squads_smart_account_program.so` in `target/deploy`.

## Build Programs

```bash
bun run anchor:build
```

The root Anchor toolchain is pinned in `Anchor.toml`. The registry crate pins its Rust-side Anchor and Light dependencies separately for Light compatibility.

## MagicBlock Local Flow

Use this only for MagicBlock-specific local testing.

Terminal 1:

```bash
bun run solana:validator
```

This starts a local validator with MagicBlock's delegation and permission programs available.

Terminal 2:

```bash
bun run magicblock:validator
```

The ephemeral validator exposes:

| Service | HTTP | WebSocket |
| --- | --- | --- |
| Solana validator | `http://127.0.0.1:8899` | `ws://127.0.0.1:8900` |
| MagicBlock ER validator | `http://127.0.0.1:7799` | `ws://127.0.0.1:7800` |

Terminal 3:

```bash
bun run anchor:test:localnet
```
