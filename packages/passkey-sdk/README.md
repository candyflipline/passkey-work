# Loyal Passkey SDK

TypeScript helpers for Loyal's pooled passkey and wallet smart-account flow.

The package has two public entrypoints:

- `@loyal/passkey-sdk` exports server-safe helpers for addresses, challenge bytes, instruction builders, and transaction plans.
- `@loyal/passkey-sdk/browser` adds WebAuthn helpers for creating passkeys, requesting assertions, and deriving the PRF-backed Solana authority.

## Install

From the workspace:

```bash
bun install
bun run sdk:build
```

After publishing:

```bash
bun add @loyal/passkey-sdk
```

## Browser Passkey Registration

```ts
import {
  buildRegistrationChallenge,
  buildSponsoredTransactionForAuthority,
  createPasskeyAuthorityInstruction,
  createPasskeyCredential,
  createPasskeySecp256r1Instruction,
  defaultPrfSalt,
  derivePrfAuthority,
  getPasskeyAssertion,
} from "@loyal/passkey-sdk/browser";

const credential = await createPasskeyCredential({
  userName: user.id,
});
const prfAuthority = await derivePrfAuthority({
  credentialId: credential.credentialId,
  prfSalt: await defaultPrfSalt(credential.credentialIdHash),
  transports: credential.transports,
});

const challenge = buildRegistrationChallenge({
  credentialIdHash: credential.credentialIdHash,
  passkeyPublicKey: credential.passkeyPublicKey,
  ed25519Authority: prfAuthority.publicKey,
  addressTree,
  squadsSettings,
  vaultIndex,
});
const assertion = await getPasskeyAssertion({
  credentialId: credential.credentialId,
  challenge,
  transports: credential.transports,
});

const secp256r1Instruction = await createPasskeySecp256r1Instruction({
  passkeyPublicKey: credential.passkeyPublicKey,
  assertion,
});
const createAuthorityInstruction = createPasskeyAuthorityInstruction({
  authority: prfAuthority.publicKey,
  poolAllocator,
  lightRemainingAccounts,
  proof,
  addressTreeInfo,
  outputStateTreeIndex,
  secp256r1InstructionIndex: 0,
  credentialIdHash: credential.credentialIdHash,
  passkeyPublicKey: credential.passkeyPublicKey,
  assertion,
});

const transaction = buildSponsoredTransactionForAuthority({
  sponsorFeePayer,
  authority: prfAuthority.keypair,
  recentBlockhash,
  instructions: [secp256r1Instruction, createAuthorityInstruction],
});
```

## Wallet Authority Registration

```ts
import {
  createWalletAuthorityInstruction,
  deriveWalletAuthorityAddress,
  walletAuthorityHash,
} from "@loyal/passkey-sdk";

const authorityHash = await walletAuthorityHash(walletPublicKey);
const authorityAddress = deriveWalletAuthorityAddress(authorityHash, addressTree);

const instruction = createWalletAuthorityInstruction({
  authority: walletPublicKey,
  poolAllocator,
  lightRemainingAccounts,
  proof,
  addressTreeInfo,
  outputStateTreeIndex,
});
```

The wallet authority signs the Solana transaction directly. It does not need a `secp256r1` precompile instruction.

## Execution

Passkey execution signs a WebAuthn challenge over the Squads payload and forwarded account metas:

```ts
import {
  buildExecutionChallenge,
  buildUnsignedSponsoredTransaction,
  createExecutePasskeyVaultTransactionInstruction,
  createPasskeySecp256r1Instruction,
  getPasskeyAssertion,
} from "@loyal/passkey-sdk/browser";

const challenge = await buildExecutionChallenge({
  credentialIdHash: authority.credentialIdHash,
  passkeyPublicKey: authority.passkeyPublicKey,
  ed25519Authority: authority.ed25519Authority,
  squadsSettings: authority.squadsSettings,
  vaultIndex: authority.vaultIndex,
  nonce: authority.nonce,
  expiresAtUnixTimestamp,
  squadsPayload,
  squadsAccounts: squadsInstructionAccounts,
});
const assertion = await getPasskeyAssertion({ credentialId, challenge });
const secp256r1Instruction = await createPasskeySecp256r1Instruction({
  passkeyPublicKey: authority.passkeyPublicKey,
  assertion,
});
const executeInstruction = createExecutePasskeyVaultTransactionInstruction({
  payer: sponsorFeePayer,
  squadsSettings: authority.squadsSettings,
  lightRemainingAccounts,
  squadsInstructionAccounts,
  proof,
  accountMeta,
  secp256r1InstructionIndex: 0,
  expectedNonce: authority.nonce,
  expiresAtUnixTimestamp,
  currentAuthority: authority,
  squadsPayload,
  assertion,
});

const transaction = buildUnsignedSponsoredTransaction({
  sponsorFeePayer,
  recentBlockhash,
  instructions: [secp256r1Instruction, executeInstruction],
});
```

Wallet execution uses the same Squads payload and Light proof accounts, but the wallet signs the Solana transaction:

```ts
import { createExecuteWalletVaultTransactionInstruction } from "@loyal/passkey-sdk";

const instruction = createExecuteWalletVaultTransactionInstruction({
  payer: feePayer,
  authority: walletPublicKey,
  squadsSettings: authority.squadsSettings,
  lightRemainingAccounts,
  squadsInstructionAccounts,
  proof,
  accountMeta,
  expectedNonce: authority.nonce,
  currentAuthority: authority,
  squadsPayload,
});
```

## Publish Check

```bash
bun run sdk:build
npm pack ./packages/passkey-sdk --pack-destination /tmp
```

`prepack` builds `dist` before packing. Generated `dist` files are not committed.
