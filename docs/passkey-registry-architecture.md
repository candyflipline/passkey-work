# Passkey Registry Architecture

This project now includes a first Solana program slice for storing passkey authority records in Light Protocol compressed PDAs. The current implementation is intentionally narrow: it proves the on-chain storage and verification path before integrating real browser WebAuthn or application UI flows.

## Current Flow

The client starts with two pieces of key material: a passkey P-256 public key and a Solana Ed25519 authority derived from passkey PRF material. It then builds a registration challenge that binds the registry program id, Ed25519 authority, credential id hash, compressed P-256 public key, Light address tree, and initial nonce.

The passkey signs that challenge with P-256. The transaction includes the Solana `secp256r1` precompile instruction first, then the registry instruction. The Ed25519 authority signs the transaction as the Solana authority. On chain, the program checks that the precompile instruction contains the expected public key and message, then derives and creates the Light compressed PDA for the authority record.

The tested flow currently creates the P-256 keypair and PRF-style Ed25519 keypair inside Rust tests. Browser-created passkeys and browser PRF extension output are deliberately out of scope for this first slice.

## Program Slice

The program lives in `programs/passkey-registry`.

`create_passkey_authority` is the initial instruction. It accepts a Light validity proof, packed address tree information, a target output state tree index, a `secp256r1` instruction index, the credential hash, and the compressed P-256 public key split into prefix plus x-coordinate.

The compressed account stores the record version and status, the credential hash, the compressed passkey public key split across `passkey_pubkey_prefix` and `passkey_pubkey_x`, the Ed25519 authority pubkey, and a nonce.

The compressed PDA address is derived from:

```text
["passkey-authority", credential_id_hash]
```

plus the expected Light address tree and the passkey registry program id.

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

## Testing Strategy

The first test layer uses LiteSVM to confirm the PRF-derived Ed25519 authority behaves like a normal Solana signer/account target.

The integration test uses `light-program-test` with SBF bytecode. It starts the Light test environment and prover, creates an in-test P-256 passkey keypair, builds and signs the registration challenge, airdrops lamports to the Ed25519 authority, submits the `secp256r1` precompile instruction plus registry instruction, creates the compressed PDA, fetches the compressed account back, and verifies the stored fields.

Run it with:

```bash
bun run test:sbf
```

The SBF test path is the main correctness gate because it compiles the program to SBF and runs the Light compressed account flow instead of only testing host-side Rust.

## Current Boundaries

Implemented and tested today: Light compressed PDA creation for passkey authority records, P-256 challenge verification through the Solana `secp256r1` precompile instruction, PRF-style Ed25519 transaction signing, and Light validity proof packing through `light-program-test`.

Still out of scope: browser WebAuthn ceremony integration, browser PRF extension integration, client-side hardening for real PRF material, update/revoke/rotate/close instructions, and application UI or API routes for registration.
