# Passkey Work

This repo is Loyal's sandbox for passkey-based Solana onboarding. It currently includes:

- A Next.js App Router app under `src/app`.
- A browser PRF tester in `src/features/passkey-prf`.
- A Solana program in `programs/passkey-registry` for Light Protocol compressed authority records and pooled Squads vault assignment.
- Local docs for the program test flow under `docs/`.

## Commands

```bash
bun install
bun run dev
bun run build
bun run lint
bun run anchor:build
bun run test:sbf
```

`bun run test:sbf` is the main program correctness gate. It compiles the registry to SBF, runs the Light compressed account flow, and exercises the local Squads synchronous execution path. The Squads E2E test expects `squads_smart_account_program.so` to be available in `target/deploy`.

## Program Notes

The registry stores per-user authority records as Light compressed PDAs, assigns each record a vault index from one shared Squads settings pool, and uses a verifier PDA as the sole Squads signer for synchronous execution. Records can be controlled by either a passkey/WebAuthn flow or a regular Ed25519 wallet signer.

Start with:

- [Passkey registry architecture](./docs/passkey-registry-architecture.md)
- [Sponsorship cost report](./docs/passkey-sponsorship-cost-report.md)
- [Solana localnet testing](./docs/solana/localnet-testing.md)
