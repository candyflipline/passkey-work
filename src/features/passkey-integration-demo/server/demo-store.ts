import {
  derivePasskeyAuthorityAddress,
  deriveSmartAccountAddressesForAuthority,
  deriveSquadsSettings,
  deriveWalletAuthorityAddress,
  walletAuthorityHash,
  type CompressedP256PublicKey,
  type PasskeyAuthorityRecord,
} from "@loyal/passkey-sdk";
import { PublicKey } from "@solana/web3.js";
import { bytesFromHex, bytesToHex, randomBytes } from "../server/encoding";
import type { DemoAccount, SerializedP256PublicKey } from "../types";

type PendingPasskeyRegistration = {
  id: string;
  account: DemoAccount;
  credentialIdHash: Uint8Array;
  passkeyPublicKey: CompressedP256PublicKey;
  ed25519Authority: PublicKey;
  registrationChallenge: Uint8Array;
};

type DemoStore = {
  passkeysByP256: Map<string, DemoAccount>;
  passkeysByRegistrationId: Map<string, PendingPasskeyRegistration>;
  passkeyLoginChallengesById: Map<string, Uint8Array>;
  walletsByAddress: Map<string, DemoAccount>;
};

const globalStore = globalThis as typeof globalThis & {
  loyalPasskeyDemoStore?: DemoStore;
};

export function getDemoStore() {
  globalStore.loyalPasskeyDemoStore ??= {
    passkeysByP256: new Map(),
    passkeysByRegistrationId: new Map(),
    passkeyLoginChallengesById: new Map(),
    walletsByAddress: new Map(),
  };

  return globalStore.loyalPasskeyDemoStore;
}

export function createRegistrationId() {
  return bytesToHex(randomBytes(16));
}

export function p256KeyId(publicKey: SerializedP256PublicKey | CompressedP256PublicKey) {
  const x = typeof publicKey.x === "string" ? publicKey.x : bytesToHex(publicKey.x);

  return `${publicKey.prefix}:${x}`;
}

export function serializeP256PublicKey(publicKey: SerializedP256PublicKey) {
  if (publicKey.prefix !== 2 && publicKey.prefix !== 3) {
    throw new Error("P-256 public key prefix must be 2 or 3.");
  }

  const x = bytesFromHex(publicKey.x);

  if (x.length !== 32) {
    throw new Error("P-256 public key x-coordinate must be 32 bytes.");
  }

  return {
    prefix: publicKey.prefix,
    x,
  } satisfies CompressedP256PublicKey;
}

export function accountFromAuthorityRecord({
  accountId,
  authorityKind,
  authority,
}: {
  accountId: string;
  authorityKind: "passkey" | "wallet";
  authority: PasskeyAuthorityRecord;
}) {
  const { vault } = deriveSmartAccountAddressesForAuthority(authority);

  return {
    accountId,
    kind: authorityKind,
    authority: authority.ed25519Authority.toBase58(),
    authorityAddress: accountId,
    createdAt: new Date().toISOString(),
    vaultIndex: authority.vaultIndex,
    squadsSettings: authority.squadsSettings.toBase58(),
    vault: vault.toBase58(),
  } satisfies DemoAccount;
}

export function createPasskeyAccount({
  credentialIdHash,
  passkeyPublicKey,
  ed25519Authority,
}: {
  credentialIdHash: Uint8Array;
  passkeyPublicKey: CompressedP256PublicKey;
  ed25519Authority: PublicKey;
}) {
  const squadsSettings = deriveSquadsSettings(0)[0];
  const authorityAddress = derivePasskeyAuthorityAddress(credentialIdHash);

  return accountFromAuthorityRecord({
    accountId: authorityAddress.toBase58(),
    authorityKind: "passkey",
    authority: {
      version: 1,
      status: 1,
      authorityKind: 0,
      credentialIdHash,
      passkeyPublicKey,
      ed25519Authority,
      squadsSettings,
      vaultIndex: 0,
      nonce: BigInt(0),
    },
  });
}

export async function createWalletAccount(walletAddress: PublicKey) {
  const hash = await walletAuthorityHash(walletAddress);
  const authorityAddress = deriveWalletAuthorityAddress(hash);
  const squadsSettings = deriveSquadsSettings(0)[0];

  return accountFromAuthorityRecord({
    accountId: authorityAddress.toBase58(),
    authorityKind: "wallet",
    authority: {
      version: 1,
      status: 1,
      authorityKind: 1,
      credentialIdHash: new Uint8Array(32),
      passkeyPublicKey: { prefix: 2, x: new Uint8Array(32) },
      ed25519Authority: walletAddress,
      squadsSettings,
      vaultIndex: 1,
      nonce: BigInt(0),
    },
  });
}

export function savePendingRegistration(registration: PendingPasskeyRegistration) {
  getDemoStore().passkeysByRegistrationId.set(registration.id, registration);
}

export function takePendingRegistration(registrationId: string) {
  const store = getDemoStore();
  const registration = store.passkeysByRegistrationId.get(registrationId);

  if (registration) {
    store.passkeysByRegistrationId.delete(registrationId);
  }

  return registration ?? null;
}

export function savePasskeyLoginChallenge(loginId: string, challenge: Uint8Array) {
  getDemoStore().passkeyLoginChallengesById.set(loginId, challenge);
}

export function takePasskeyLoginChallenge(loginId: string) {
  const store = getDemoStore();
  const challenge = store.passkeyLoginChallengesById.get(loginId);

  if (challenge) {
    store.passkeyLoginChallengesById.delete(loginId);
  }

  return challenge ?? null;
}
