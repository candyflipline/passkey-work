import type { SerializedP256PublicKey } from "../types";

export type StoredDemoPasskey = {
  label: string;
  credentialId: string;
  credentialIdHash: string;
  passkeyPublicKey: SerializedP256PublicKey;
  authority: string;
  createdAt: string;
};

const STORAGE_KEY = "loyal.passkey-demo.credentials.v1";

export function listStoredDemoPasskeys() {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const value = window.localStorage.getItem(STORAGE_KEY);

    return value ? (JSON.parse(value) as StoredDemoPasskey[]) : [];
  } catch {
    return [];
  }
}

export function saveStoredDemoPasskey(passkey: StoredDemoPasskey) {
  const passkeys = listStoredDemoPasskeys().filter(
    (stored) => stored.credentialIdHash !== passkey.credentialIdHash,
  );

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify([passkey, ...passkeys].slice(0, 5)));
}
