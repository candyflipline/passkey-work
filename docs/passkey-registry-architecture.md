# Passkey Registry Architecture

This project includes a Solana program slice for storing user authority records in Light Protocol compressed PDAs and assigning those records to pooled Squads smart-account vault indexes. The implementation is intentionally narrow: it proves cheap on-chain storage, assigns vault indexes, and routes execution through the verifier before integrating full application UI flows. The SBF test suite covers the local path from Squads smart-account creation through passkey-authorized and wallet-authorized vault execution.

## Current Flow

The passkey path starts with two pieces of key material: a passkey P-256 public key and a Solana Ed25519 authority derived from passkey PRF material. The wallet path starts with a normal Ed25519 wallet signer. Both paths target a Squads pool settings account whose sole signer is the registry verifier PDA.

Before registration, the pool has one Light-PDA allocator:

```text
["pool-allocator", squads_settings]
```

The allocator stores version, status, `squads_settings`, `next_index`, its bump, and the surplus withdrawal authority. It uses monotonic allocation from index `0` through `255`; there is no bitmap or slot reuse in the MVP. Because the allocator is a Light PDA, it remains cheap to create but can still hold SOL for rollover float and sign with the registry seeds.

Pool discovery is tracked separately from per-user allocation. A single Light compressed PDA acts as the pool directory:

```text
["pool-directory"]
```

The directory stores version, status, and `active_pool_index`. That index is the deterministic Squads settings seed used to derive the currently active settings PDA:

```text
["smart_account", "settings", active_pool_index]
```

Clients read the compressed directory to find the active Squads settings account, derive that pool's allocator, and submit registration against that allocator. Registration itself does not update the directory, so the hot path stays one allocator write plus one compressed user authority record creation.

For passkeys, the registration challenge binds the registry program id, Ed25519 authority, credential id hash, compressed P-256 public key, Light address tree, assigned Squads settings account, assigned vault index, and initial nonce.

The passkey signs that challenge with P-256. The transaction includes the Solana `secp256r1` precompile instruction first, then the registry instruction. The Ed25519 authority signs the transaction as the Solana authority. On chain, the program checks that the precompile instruction contains the expected public key and message, verifies the allocator's current index, increments the allocator, then derives and creates the Light compressed PDA for the authority record.

For regular wallets, `create_wallet_authority` skips the WebAuthn challenge and uses the wallet's Ed25519 transaction signature as the authority check. The compressed PDA is domain-separated from passkey records with `LOYAL_WALLET_AUTHORITY_V1`, stores `authority_kind = wallet`, and still receives a pooled Squads vault index from the same allocator.

When an allocator reaches `next_index = 256`, the current Squads settings pool is full. The provisioning flow calls `provision_next_pool`. That instruction verifies the current allocator is exhausted, derives the following Squads settings account at `active_pool_index + 1`, prefunds that settings account from the current allocator, CPIs into Squads to create the smart account, initializes the next Light-PDA allocator, moves the configured rollover float into it, and updates the compressed directory index by one.

The outer fee payer still submits the transaction and pays transaction fees. The allocator SOL sponsors account creation rent and top-ups inside the instruction.

The SBF tests still use an in-test P-256 keypair and PRF-style Ed25519 keypair, but the verifier now checks the same signed message shape that browser WebAuthn assertions produce: `authenticatorData || sha256(clientDataJSON)`. Browser SDK helpers for this flow live in `src/features/passkey-smart-account` and are summarized in `docs/passkey-browser-sdk.md`.

The end-to-end Squads tests create the Squads settings account locally with only the verifier PDA as signer, initialize the registry allocator against that settings account, create compressed authority records, fund vault index `0`, and then move SOL back out of that vault through Squads synchronous execution using either a passkey challenge or a wallet signature.

## Program Slice

The program lives in `programs/passkey-registry`.

`initialize_pool_allocator` creates the hot Light-PDA allocator for one Squads settings pool. It takes the actual Squads settings account, validates that it is the static verifier-owned shape expected by this design, and derives the allocator PDA from that settings key.

`fund_pool_allocator` lets anyone top up the active allocator with SOL for future rollover.

`withdraw_pool_allocator_surplus` lets the configured withdrawal authority recover surplus SOL while enforcing a caller-supplied minimum balance to keep in the allocator.

`initialize_pool_directory` creates the compressed pool directory for the first active Squads settings index. It validates the supplied settings account and allocator before storing the active index.

`provision_next_pool` rolls the system to the next Squads settings pool. It refuses to advance early while the current allocator still has capacity, creates the following settings account through Squads, initializes the next Light-PDA allocator, transfers rollover float, and updates the compressed directory through a Light state transition.

`create_passkey_authority` registers a user. It accepts a Light validity proof, packed address tree information, a target output state tree index, a `secp256r1` instruction index, the credential hash, and the compressed P-256 public key split into prefix plus x-coordinate. The vault index is not supplied by the client as trusted input; it is read from the allocator and signed in the passkey challenge.

`create_wallet_authority` registers a regular Ed25519 wallet signer. It accepts the same Light creation inputs, reads the vault index from the allocator, hashes the wallet pubkey under `LOYAL_WALLET_AUTHORITY_V1`, and creates the same compressed authority record with zeroed passkey-key fields.

`execute_passkey_vault_transaction` updates the compressed nonce and CPIs into Squads `execute_transaction_sync_v2`. The verifier PDA signs the Squads CPI with program seeds and is expected to be the only Squads signer in the pool settings account. The passkey execution challenge binds the verifier PDA, Squads program id, settings account, vault index, nonce, expiry, payload hash, and remaining account metas hash.

`execute_wallet_vault_transaction` uses the same nonce update and Squads CPI path, but requires the stored Ed25519 authority to sign the Solana transaction instead of requiring a P-256 precompile instruction.

The compressed account stores the record version and status, `authority_kind`, the credential or wallet authority hash, the compressed passkey public key split across `passkey_pubkey_prefix` and `passkey_pubkey_x`, the Ed25519 authority pubkey, the Squads settings pubkey, the `u8` vault index, and a nonce. Wallet records set the passkey-key fields to zero.

The passkey compressed PDA uses these seeds:

```text
["passkey-authority", credential_id_hash]
```

plus the expected Light address tree and the passkey registry program id.

Wallet records add a domain separator:

```text
["passkey-authority", "LOYAL_WALLET_AUTHORITY_V1", wallet_authority_hash]
```

where `wallet_authority_hash = hashv(["LOYAL_WALLET_AUTHORITY_V1", wallet_pubkey])`.

The compressed pool directory is keyed by:

```text
["pool-directory"]
```

plus the expected Light address tree and the passkey registry program id.

The Squads vault PDA is not stored. It is derived when needed from the Squads seeds:

```text
["smart_account", squads_settings, "smart_account", vault_index]
```

plus the Squads smart account program id.

## Why Pooled Squads Settings

Creating one Squads settings account per user would bring back the per-user sponsorship cost this design is trying to avoid. Instead, one static Squads settings account is amortized across the full `u8` vault index space.

The intended Squads settings configuration is:

```text
threshold = 1
time_lock = 0
signer = registry verifier PDA with Initiate + Vote + Execute
```

Users are not added as Squads signers, and the registry does not update Squads settings during user registration. The registry allocator owns vault assignment. Squads `account_utilization` remains outside this flow.

Allocator initialization and execution both check the supplied Squads settings account: it must be owned by the Squads program, have `settings_authority = Pubkey::default()`, `threshold = 1`, `time_lock = 0`, and exactly one full-permission signer, the verifier PDA.

The program uses all 256 possible vault indexes unless a future product decision explicitly reserves one.

The directory/allocator split is deliberate. Putting the active pool cursor into the allocator would force clients to either know which allocator is current already or scan every allocator to find capacity. Updating the directory on every registration would make the compressed cursor part of the hot path. The current shape keeps the allocator hot and lamport-capable, while the compressed directory is touched only on pool creation and rollover.

One Squads constraint matters for sponsorship: Squads creates settings through the System Program, and a data-carrying allocator cannot be the direct System Program transfer source. The registry handles that by directly moving allocator lamports into the new settings PDA before the Squads CPI. Squads then sees the settings PDA already rent-funded and only allocates and assigns it. The pooled path therefore requires the target Squads program config to have a zero smart-account creation fee.

## Squads Execution Path

The passkey user supplies the Squads transaction payload they want the vault to execute. The registry does not trust that payload by itself. It hashes both the serialized Squads payload and the remaining Squads account metas, then requires the passkey to sign an execution challenge that binds the registry program, Squads program, verifier signer, stored Ed25519 authority, credential id hash, P-256 public key, settings account, vault index, replay nonce, expiry timestamp, payload hash, and account-metas hash.

After the `secp256r1` instruction check passes, the registry increments the compressed account nonce through a Light state update and CPIs into Squads `execute_transaction_sync_v2`. Squads receives the verifier PDA as its threshold signer. For vault execution, Squads derives the smart-account PDA from the settings account and `account_index`, marks that PDA as the signer for the inner instruction, and invokes the requested transaction payload.

The wallet execution path is shorter: the wallet signs the Solana transaction, the registry verifies that the signer matches the stored `ed25519_authority`, increments the same compressed nonce, and uses the same verifier-signed Squads CPI.

The current SBF tests cover native SOL transfers from Squads vault `0` to recipients. The passkey test uses a signed registry execution challenge, the wallet test uses the stored Ed25519 authority signer, and both Squads CPIs are signed by the verifier PDA through `invoke_signed`.

## Why Light Protocol Compressed PDAs

Authority records are per-user state. Creating one normal Solana account per user would require rent-exempt account sponsorship up front. A Light compressed PDA keeps the state addressable by the program while avoiding that rent-heavy account model.

This matches the product direction: registration should be cheap enough to support early onboarding, while still producing a canonical on-chain record that later instructions can reference.

The 256-user rent comparison is tracked in `docs/passkey-sponsorship-cost-report.md`.

## Why Split Passkey Proof From Solana Authority

The architecture keeps two roles separate. The passkey P-256 key proves that the passkey participated in registration by signing the challenge checked through the `secp256r1` precompile. The Ed25519 key derived from PRF material acts as a normal Solana transaction authority and signs the transaction.

This avoids pretending that the WebAuthn PRF output is directly attested by the authenticator. The passkey signature proves the registration ceremony. The Ed25519 signer proves control of the Solana authority used for the compressed PDA record.

The registration challenge binds both roles together by including the Ed25519 authority and the passkey public key in the same signed message. Regular wallet records do not use this split; the wallet's Ed25519 signature is the authority proof.

## Why Store Prefix Plus X-Coordinate

Compressed P-256 public keys are 33 bytes: a one-byte parity prefix plus a 32-byte x-coordinate. The account state stores these as `passkey_pubkey_prefix: u8` and `passkey_pubkey_x: [u8; 32]`.

That shape avoids awkward fixed-array derive behavior around `[u8; 33]` while still preserving the full compressed SEC1 public key. The program reconstructs the 33-byte key before checking the `secp256r1` instruction.

## Why Check The Address Tree

Light compressed PDA derivation includes the address tree. The program checks that the packed address tree resolves to the expected `ADDRESS_TREE_V2` tree before creating the record.

That prevents the client and program from silently deriving different compressed addresses or accepting a record under an unexpected tree.

## Token Account Sponsorship

The registry derives vaults but does not pre-create token accounts or ATAs for those vaults. Token accounts should be created lazily only when a user actually needs a specific mint; otherwise token account rent becomes a hidden per-user sponsorship cost.

## Replay State Tradeoff

The MVP keeps the replay nonce inside `PasskeyAuthority`, which now represents either a passkey or wallet authority. That minimizes account count and keeps onboarding to one compressed record per user. The tradeoff is that every execution touches compressed state and therefore pays the Light proof and state-tree costs. If some users become high frequency, replay protection can later move to a small hot nonce PDA or compressed nullifier path without changing the pooled Squads assignment model.

## Testing Strategy

The first test layer uses LiteSVM to confirm the PRF-derived Ed25519 authority behaves like a normal Solana signer/account target.

The registration integration tests use `light-program-test` with SBF bytecode. They start the Light test environment and prover, initialize a pool allocator, create compressed PDAs for passkey and wallet authorities, fetch the compressed accounts back, and verify the stored fields and allocator increment.

The pool-directory integration tests create the compressed directory, verify it points at Squads settings seed `1`, simulate an exhausted allocator with mixed passkey and wallet registrations, call `provision_next_pool`, verify the next allocator starts at index `0`, check lamports moved from the old allocator to the new settings account and next allocator, and register a wallet against the new pool. A separate test confirms rollover fails while the current allocator still has free slots.

The end-to-end Squads integration tests also load the real Squads smart-account SBF program. They seed the Squads program config in the local LiteSVM environment, create a Squads settings account with a single full-permission verifier signer, initialize the registry allocator, create compressed authorities at vault index `0`, fund the vault, execute passkey-authorized and wallet-authorized Squads sync transfers, and verify both lamport movement and nonce increment. A negative wallet test confirms the wrong Ed25519 signer cannot spend through another wallet record.

Run it with:

```bash
bun run test:sbf
```

The SBF test path is the main correctness gate because it compiles the registry program to SBF and runs the Light compressed account flow instead of only testing host-side Rust. The Squads E2E test expects a Squads SBF binary named `squads_smart_account_program.so` in `target/deploy` so `light-program-test` can load it as an additional program.

## Current Boundaries

Implemented and tested today: Light-PDA allocator initialization, allocator funding and admin-gated surplus withdrawal, compressed pool-directory initialization and rollover, allocator-funded Squads settings creation, monotonic vault assignment, Light compressed PDA creation for passkey and wallet authority records, browser-compatible WebAuthn/P-256 challenge verification through the Solana `secp256r1` precompile instruction, PRF-style Ed25519 transaction signing, wallet signer registration and execution, Light validity proof packing through `light-program-test`, Squads settings creation with verifier PDA signing, passkey-authorized and wallet-authorized Squads sync execution from vault index `0`, and a browser-side TypeScript SDK surface for passkey creation, PRF authority derivation, address derivation, instruction packing, and user-paid or sponsored transaction assembly.

Still out of scope: production Squads pool provisioning, exact Squads settings rent measurement on the target deployment, update/revoke/rotate/close instructions, slot reuse/bitmap allocation, high-frequency hot nonce promotion, and application UI or API routes for registration.
