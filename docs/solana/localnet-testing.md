# Localnet Testing

This is the local Solana and MagicBlock setup copied from Loyal's app repo and generalized for this project before any programs exist.

## Prerequisites

- Solana CLI (`solana-test-validator`)
- Anchor CLI (`anchor`)
- MagicBlock Solana validator (`mb-test-validator`)
- MagicBlock Ephemeral validator (`ephemeral-validator`)

## Build Programs

After adding a program under `programs/<program-name>`, build it with:

```bash
NO_DNA=1 anchor build
```

## Start Solana Validator

Run in terminal 1:

```bash
NO_DNA=1 mb-test-validator \
  --reset \
  --ledger ~/test-ledger \
  --url devnet \
  --clone-upgradeable-program DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh \
  --clone-upgradeable-program ACLseoPoyC3cBqoUtkbjZ4aDrkurZW86v19pXz2XQnp1
```

This starts a local validator with MagicBlock's delegation and permission programs available.

## Start MagicBlock Ephemeral Validator

Run in terminal 2:

```bash
NO_DNA=1 RUST_LOG=info ephemeral-validator \
  --accounts-lifecycle ephemeral \
  --remote-cluster development \
  --remote-url http://127.0.0.1:8899 \
  --remote-ws-url ws://127.0.0.1:8900 \
  --rpc-port 7799
```

The ephemeral validator exposes:

| Service | HTTP | WebSocket |
| --- | --- | --- |
| Solana validator | `http://127.0.0.1:8899` | `ws://127.0.0.1:8900` |
| MagicBlock ER validator | `http://127.0.0.1:7799` | `ws://127.0.0.1:7800` |

## Run Tests

After adding tests under `tests/**/*.ts`, run in terminal 3:

```bash
EPHEMERAL_PROVIDER_ENDPOINT="http://localhost:7799" \
EPHEMERAL_WS_ENDPOINT="ws://localhost:7800" \
NO_DNA=1 anchor test \
  --provider.cluster localnet \
  --skip-local-validator \
  --skip-build \
  --skip-deploy
```

If a future test should let Anchor start the local validator for you, keep the MagicBlock clone entries in `Anchor.toml` and run:

```bash
NO_DNA=1 anchor test
```
