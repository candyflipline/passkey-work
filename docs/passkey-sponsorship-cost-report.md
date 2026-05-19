# Passkey and Smart-Account Sponsorship Cost Report

This report compares the rent reserve needed to sponsor one-signer smart accounts versus the current compressed PDA plus pooled Squads smart-account model. The 10,000-user simulation uses a direct baseline of one Squads smart account per user with one Ed25519 signer. It also includes a sensitivity case for the older direct model where each user gets both a normal authority PDA and a Squads settings account.

## Scope

The comparison is rent only. It excludes transaction fees, compute priority fees, secp256r1 verification cost, Light proof/state-tree fees, any Squads creation fee, and user funds deposited into vaults. Those costs still matter for production pricing, but they are separate from the rent that has to be locked up to create Solana accounts.

The rent math uses Solana's default rent-exempt minimum:

```text
minimum_balance(data_len) = (128 + data_len) * 3,480 * 2 lamports
```

That is the SDK default `Rent::minimum_balance` formula, with the 128-byte account storage overhead, 3,480 lamports per byte-year, and a 2-year exemption threshold.

## Account Sizes Used

| Account | Data bytes | Rent per account |
| --- | ---: | ---: |
| Normal `PasskeyAuthority` PDA | 149 | 1,927,920 lamports / 0.00192792 SOL |
| Squads `Settings` account, 1 signer | 168 | 2,060,160 lamports / 0.00206016 SOL |
| Registry `PoolAllocator` Light PDA | 101 | 1,593,840 lamports / 0.00159384 SOL |
| Compressed `PoolDirectory` cursor | 18 compressed bytes | No rent-exempt account |

The normal authority PDA estimate assumes the current `PasskeyAuthority` payload stored as a regular Anchor account: 8 bytes of account discriminator plus 141 bytes of authority data. The authority data is:

```text
version: 1
status: 1
authority_kind: 1
credential_id_hash: 32
passkey_pubkey_prefix: 1
passkey_pubkey_x: 32
ed25519_authority: 32
squads_settings: 32
vault_index: 1
nonce: 8
total data: 141 bytes
```

The Squads settings estimate follows the local Squads smart-account program used by the SBF test. With one verifier signer, `Settings::size(1)` is 168 bytes. The current pooled route also creates one Light-PDA `PoolAllocator` for the whole Squads settings pool and one compressed `PoolDirectory` cursor for discovering the active pool.

## 10,000 User Simulation

The simulation lives at `scripts/simulate-sponsorship-costs.mjs` and was run with:

```text
node scripts/simulate-sponsorship-costs.mjs
```

Inputs:

| Input | Value |
| --- | ---: |
| Requested users | 10,000 |
| Vault slots per pooled Squads settings account | 256 |
| Pooled settings accounts needed | 40 |
| Pooled smart-account capacity created | 10,240 |
| Unused slots in final pool | 240 |

Results:

| Route | Sponsored account shape | Total rent reserve |
| --- | --- | ---: |
| Direct one-signer smart accounts | 10,000 Squads settings accounts, each with one Ed25519 signer | 20,601,600,000 lamports / 20.6016 SOL |
| Current pooled route | 10,000 compressed authority records + 40 Squads settings accounts + 40 allocator Light PDAs + 1 compressed directory cursor | 146,160,000 lamports / 0.14616 SOL |
| Direct route with normal authority PDAs | 10,000 normal authority PDAs + 10,000 Squads settings accounts | 39,880,800,000 lamports / 39.8808 SOL |

The pooled route cuts rent by about 141.0x compared with sponsoring 10,000 direct one-signer Squads smart accounts. It leaves 20.45544 SOL unlocked, a 99.29% rent-reserve reduction.

Against the direct route that also stores one normal authority PDA per user, the same pooled design cuts rent by about 272.9x. It leaves 39.73464 SOL unlocked, a 99.63% rent-reserve reduction.

For the requested 10,000 users, the pooled route amortizes to 14,616 lamports, or 0.000014616 SOL, per requested user. Across the 10,240 vault slots created by the 40 pools, the reserve is 14,273.4375 lamports, or 0.0000142734375 SOL, per available slot.

## 256 User Comparison

| Route | Accounts sponsored | Total rent reserve |
| --- | --- | ---: |
| Direct route | 256 normal authority PDAs + 256 Squads settings accounts | 1,020,948,480 lamports / 1.02094848 SOL |
| Current pooled route | 256 compressed authority records + 1 Squads settings account + 1 allocator Light PDA + 1 compressed directory cursor | 3,654,000 lamports / 0.003654 SOL |

Per user, the direct route requires 3,988,080 lamports, or 0.00398808 SOL, before transaction fees. The pooled route amortizes to 14,273.4375 lamports, or 0.0000142734375 SOL, of rent reserve per available vault slot across the 256-user pool.

That means the current pooled route uses about 279.4x less rent than the direct route for a full 256-user pool. It removes 1.01729448 SOL of rent reserve from this 256-user sponsorship batch, a 99.64% reduction in rent locked up for account creation.

## Why The Current Logic Supports This

The SBF end-to-end tests exercise the same account shape used by the cost model. They load the passkey registry SBF program and the real Squads smart-account SBF program, create one Squads settings account with the registry verifier PDA as the only signer, initialize one allocator PDA for that settings account, create Light compressed authority records at vault index `0`, fund the derived Squads vault, and execute verifier-signed Squads synchronous transfers for passkey and wallet authorities.

The smart-account side is the key savings lever. Squads vaults are deterministic PDA namespaces under one settings account, so the pooled route does not create 256 Squads settings accounts. The registry stores only the authority binding, `squads_settings`, `vault_index`, and nonce in the compressed record, derives the vault PDA when needed, and uses its verifier PDA as the sole Squads signer for synchronous execution.

Pool discovery is handled by a compressed `PoolDirectory` cursor. The cursor stores the active Squads settings index and is updated only when the active allocator reaches `next_index = 256` and a new Squads settings pool is provisioned. The active allocator can hold SOL for rollover: it prefunds the next Squads settings account, moves configured float to the next allocator, and leaves transaction fees to the outer payer.

## Caveats

The comparison covers the rent-reserve argument. Production pricing should add Light compression fees, proof generation/RPC costs, Solana transaction fees, and any target Squads deployment creation fee. Token accounts are also intentionally excluded because the current design does not pre-create ATAs; they should be sponsored lazily only when a user actually needs a mint.
