# Passkey Browser SDK

The browser SDK lives in `src/features/passkey-smart-account`. It packages the pieces the web app needs to integrate with the registry and pooled Squads vault flow: WebAuthn passkey creation, P-256 public-key extraction, PRF evaluation for the Ed25519 Solana authority seed, registration and execution challenge builders, PDA derivation, `secp256r1` precompile instruction packing, registry instruction packing, wallet-authority instruction packing, and immutable transaction-plan helpers for user-paid or backend-sponsored transactions.

## Data Flow

Registration is a three-step browser flow:

1. `createPasskeyCredential` creates a resident ES256 passkey, extracts the compressed P-256 public key, hashes the credential id, and records whether the authenticator supports PRF.
2. `derivePrfAuthority` asks the same credential to evaluate the PRF salt and turns the 32-byte PRF output into a Solana `Keypair.fromSeed` authority. This authority signs registration as the Solana signer.
3. After the app has the active pool data from Solana, `buildRegistrationChallenge` constructs the exact challenge that the program expects. `getPasskeyAssertion` signs it through WebAuthn, and `createPasskeySecp256r1Instruction` packs the assertion into the Solana P-256 precompile instruction.

The registry stores `authorityKind`, the credential or wallet authority hash, compressed P-256 key fields, Ed25519 authority, Squads settings address, vault index, and nonce in the compressed `PasskeyAuthority` record. The vault address is then derived from `squads_settings` plus `vault_index`; it is not derivable from the P-256 key or wallet pubkey alone unless the matching authority record has already been fetched and decoded. Use `deriveSmartAccountAddressesForPasskeyPublicKey` when the browser has both the P-256 key and decoded passkey record.

Regular wallet records use `walletAuthorityHash(authority)` and `deriveWalletAuthorityAddress(...)`, then pack `createWalletAuthorityInstruction` with the same Light proof and allocator accounts used by passkey registration. Wallet execution uses `createExecuteWalletVaultTransactionInstruction`; the wallet authority signs the Solana transaction and no `secp256r1` instruction is included.

Execution uses the same WebAuthn assertion shape. `buildExecutionChallenge` binds the stored authority record, nonce, expiry, Squads payload hash, and forwarded Squads account metas. The registry verifies the `secp256r1` instruction against `authenticatorData || sha256(clientDataJSON)`, checks that `clientDataJSON.challenge` equals the expected challenge, bumps the compressed nonce, and CPIs into Squads synchronous execution.

## Fee Payer Shapes

For user-paid registration, build the two-instruction transaction with the PRF authority as fee payer and signer:

```ts
const transaction = buildUserPaidTransaction({
  authority: prfAuthority.keypair,
  recentBlockhash,
  instructions: [secp256r1Instruction, createAuthorityInstruction],
});
```

For sponsored registration, set the backend sponsor as fee payer and have the browser partially sign with the PRF authority:

```ts
const transaction = buildSponsoredTransactionForAuthority({
  sponsorFeePayer,
  authority: prfAuthority.keypair,
  recentBlockhash,
  instructions: [secp256r1Instruction, createAuthorityInstruction],
});
```

For sponsored execution, the browser does not need the PRF authority as a Solana signer. It creates the passkey assertion and registry instruction, then sends an unsigned transaction to the sponsor:

```ts
const transaction = buildUnsignedSponsoredTransaction({
  sponsorFeePayer,
  recentBlockhash,
  instructions: [secp256r1Instruction, executeInstruction],
});
```

Before broadcasting, the backend should simulate the transaction, confirm the requested Squads payload and accounts are policy-acceptable, then add its fee-payer signature.
