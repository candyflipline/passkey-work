# Passkey and Smart-Account Sponsorship Cost Report

This report compares the rent reserve needed to onboard 256 passkey users with a direct one-user-one-account model versus the current compressed PDA plus pooled Squads smart-account model.

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
| Normal `PasskeyAuthority` PDA | 148 | 1,920,960 lamports / 0.00192096 SOL |
| Squads `Settings` account, 1 signer | 168 | 2,060,160 lamports / 0.00206016 SOL |
| Registry `PoolAllocator` PDA | 44 | 1,197,120 lamports / 0.00119712 SOL |

The normal passkey PDA estimate assumes the current `PasskeyAuthority` payload stored as a regular Anchor account: 8 bytes of account discriminator plus 140 bytes of authority data. The authority data is:

```text
version: 1
status: 1
credential_id_hash: 32
passkey_pubkey_prefix: 1
passkey_pubkey_x: 32
ed25519_authority: 32
squads_settings: 32
vault_index: 1
nonce: 8
total data: 140 bytes
```

The Squads settings estimate follows the local Squads smart-account program used by the SBF test. With one verifier signer, `Settings::size(1)` is 168 bytes. The current pooled route also creates one tiny `PoolAllocator` PDA for the whole Squads settings pool.

## 256 User Comparison

| Route | Accounts sponsored | Total rent reserve |
| --- | --- | ---: |
| Direct route | 256 normal passkey PDAs + 256 Squads settings accounts | 1,019,166,720 lamports / 1.01916672 SOL |
| Current pooled route | 256 compressed passkey records + 1 Squads settings account + 1 allocator PDA | 3,257,280 lamports / 0.00325728 SOL |

Per user, the direct route requires 3,981,120 lamports, or 0.00398112 SOL, before transaction fees. The pooled route amortizes to 12,723.75 lamports, or 0.00001272375 SOL, of rent reserve per available vault slot across the 256-user pool.

That means the current pooled route uses about 312.9x less rent than the direct route for a full 256-user pool. It removes 1.01590944 SOL of rent reserve from this 256-user sponsorship batch, a 99.68% reduction in rent locked up for account creation.

## Why The Current Logic Supports This

The SBF end-to-end test exercises the same account shape used by the cost model. It loads the passkey registry SBF program and the real Squads smart-account SBF program, creates one Squads settings account with the registry verifier PDA as the only signer, initializes one allocator PDA for that settings account, creates a Light compressed passkey authority record at vault index `0`, funds the derived Squads vault, and executes a verifier-signed Squads synchronous transfer.

The smart-account side is the key savings lever. Squads vaults are deterministic PDA namespaces under one settings account, so the pooled route does not create 256 Squads settings accounts. The registry stores only `squads_settings` and `vault_index` in the compressed passkey record, derives the vault PDA when needed, and uses its verifier PDA as the sole Squads signer for synchronous execution.

## Caveats

The comparison covers the rent-reserve argument. Production pricing should add Light compression fees, proof generation/RPC costs, Solana transaction fees, and any target Squads deployment creation fee. Token accounts are also intentionally excluded because the current design does not pre-create ATAs; they should be sponsored lazily only when a user actually needs a mint.
