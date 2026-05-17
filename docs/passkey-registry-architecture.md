# Passkey Registry Architecture

This project includes a Solana program slice for storing passkey authority records in Light Protocol compressed PDAs and assigning those records to pooled Squads smart-account vault indexes. The implementation is intentionally narrow: it proves cheap on-chain storage, assigns vault indexes, and routes execution through the verifier before integrating real browser WebAuthn or application UI flows.

## Current Flow

The client starts with two pieces of key material: a passkey P-256 public key and a Solana Ed25519 authority derived from passkey PRF material. It also targets an existing Squads pool settings account that has the registry verifier PDA as its sole signer.

Before registration, the pool has one tiny normal PDA allocator:

```text
["pool-allocator", squads_settings]
```

The allocator stores only version, status, `squads_settings`, `next_index`, `occupied_count`, and bump. It uses monotonic allocation from index `0` through `255`; there is no bitmap or slot reuse in the MVP.

The registration challenge binds the registry program id, Ed25519 authority, credential id hash, compressed P-256 public key, Light address tree, assigned Squads settings account, assigned vault index, and initial nonce.

The passkey signs that challenge with P-256. The transaction includes the Solana `secp256r1` precompile instruction first, then the registry instruction. The Ed25519 authority signs the transaction as the Solana authority. On chain, the program checks that the precompile instruction contains the expected public key and message, verifies the allocator's current index, increments the allocator, then derives and creates the Light compressed PDA for the authority record.

The tested flow currently creates the P-256 keypair and PRF-style Ed25519 keypair inside Rust tests. Browser-created passkeys and browser PRF extension output are deliberately out of scope for this first slice.

## Program Slice

The program lives in `programs/passkey-registry`.

`initialize_pool_allocator` creates the small hot allocator PDA for one Squads settings pool.

`create_passkey_authority` registers a user. It accepts a Light validity proof, packed address tree information, a target output state tree index, a `secp256r1` instruction index, the credential hash, and the compressed P-256 public key split into prefix plus x-coordinate. The vault index is not supplied by the client as trusted input; it is read from the allocator and signed in the passkey challenge.

`execute_passkey_vault_transaction` updates the compressed nonce and CPIs into Squads `execute_transaction_sync_v2`. The verifier PDA signs the Squads CPI with program seeds and is expected to be the only Squads signer in the pool settings account. The passkey execution challenge binds the verifier PDA, Squads program id, settings account, vault index, nonce, expiry, payload hash, and remaining account metas hash.

The compressed account stores the record version and status, the credential hash, the compressed passkey public key split across `passkey_pubkey_prefix` and `passkey_pubkey_x`, the Ed25519 authority pubkey, the Squads settings pubkey, the `u8` vault index, and a nonce.

The compressed PDA address is derived from:

```text
["passkey-authority", credential_id_hash]
```

plus the expected Light address tree and the passkey registry program id.

The Squads vault PDA is not stored. It is derived when needed from the Squads seeds:

```text
["smart_account", squads_settings, "smart_account", vault_index]
```

plus the Squads smart account program id.

## Why Pooled Squads Settings

Creating one Squads settings account per passkey user would bring back the per-user sponsorship cost this design is trying to avoid. Instead, one static Squads settings account is amortized across the full `u8` vault index space.

The intended Squads settings configuration is:

```text
threshold = 1
time_lock = 0
signer = registry verifier PDA with Initiate + Vote + Execute
```

The passkey user is not added as a Squads signer, and the registry does not update Squads settings during user registration. The registry allocator owns vault assignment. Squads `account_utilization` remains outside this flow.

The execution path rechecks the supplied Squads settings account before CPI: it must be owned by the Squads program, have `settings_authority = Pubkey::default()`, `threshold = 1`, `time_lock = 0`, and exactly one signer, the registry verifier PDA with full permissions.

The program uses all 256 possible vault indexes unless a future product decision explicitly reserves one.

## Why Light Protocol Compressed PDAs

Passkey authority records are per-user state. Creating one normal Solana account per user would require rent-exempt account sponsorship up front. A Light compressed PDA keeps the state addressable by the program while avoiding that rent-heavy account model.

This matches the product direction: registration should be cheap enough to support early onboarding, while still producing a canonical on-chain record that later instructions can reference.

## Why Split Passkey Proof From Solana Authority

The architecture keeps two roles separate. The passkey P-256 key proves that the passkey participated in registration by signing the challenge checked through the `secp256r1` precompile. The Ed25519 key derived from PRF material acts as a normal Solana transaction authority and signs the transaction.

This avoids pretending that the WebAuthn PRF output is directly attested by the authenticator. The passkey signature proves the registration ceremony. The Ed25519 signer proves control of the Solana authority used for the compressed PDA record.

The registration challenge binds both roles together by including the Ed25519 authority and the passkey public key in the same signed message.

## Why Store Prefix Plus X-Coordinate

Compressed P-256 public keys are 33 bytes: a one-byte parity prefix plus a 32-byte x-coordinate. The account state stores these as `passkey_pubkey_prefix: u8` and `passkey_pubkey_x: [u8; 32]`.

That shape avoids awkward fixed-array derive behavior around `[u8; 33]` while still preserving the full compressed SEC1 public key. The program reconstructs the 33-byte key before checking the `secp256r1` instruction.

## Why Check The Address Tree

Light compressed PDA derivation includes the address tree. The program checks that the packed address tree resolves to the expected `ADDRESS_TREE_V2` tree before creating the record.

That prevents the client and program from silently deriving different compressed addresses or accepting a record under an unexpected tree.

## Token Account Sponsorship

The registry derives vaults but does not pre-create token accounts or ATAs for those vaults. Token accounts should be created lazily only when a user actually needs a specific mint; otherwise token account rent becomes a hidden per-user sponsorship cost.

## Replay State Tradeoff

The MVP keeps the replay nonce inside `PasskeyAuthority`. That minimizes account count and keeps onboarding to one compressed record per user. The tradeoff is that every execution touches compressed state and therefore pays the Light proof and state-tree costs. If some users become high frequency, replay protection can later move to a small hot nonce PDA or compressed nullifier path without changing the pooled Squads assignment model.

## Testing Strategy

The first test layer uses LiteSVM to confirm the PRF-derived Ed25519 authority behaves like a normal Solana signer/account target.

The integration test uses `light-program-test` with SBF bytecode. It starts the Light test environment and prover, initializes a pool allocator, creates an in-test P-256 passkey keypair, builds and signs the registration challenge for allocator index `0`, airdrops lamports to the Ed25519 authority, submits the `secp256r1` precompile instruction plus registry instruction, creates the compressed PDA, fetches the compressed account back, and verifies the stored fields and allocator increment.

Run it with:

```bash
bun run test:sbf
```

The SBF test path is the main correctness gate because it compiles the program to SBF and runs the Light compressed account flow instead of only testing host-side Rust.

## Current Boundaries

Implemented and tested today: allocator initialization, monotonic vault assignment, Light compressed PDA creation for passkey authority records, P-256 challenge verification through the Solana `secp256r1` precompile instruction, PRF-style Ed25519 transaction signing, and Light validity proof packing through `light-program-test`.

Implemented but not yet covered by an end-to-end Squads test: the verifier instruction path that updates the compressed nonce and CPIs into Squads synchronous execution.

Still out of scope: browser WebAuthn ceremony integration, browser PRF extension integration, client-side hardening for real PRF material, Squads pool provisioning, exact Squads settings rent measurement on the target deployment, update/revoke/rotate/close instructions, slot reuse/bitmap allocation, high-frequency hot nonce promotion, and application UI or API routes for registration.
