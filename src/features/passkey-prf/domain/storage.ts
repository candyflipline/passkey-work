import type { StoredPasskey } from "./webauthn";

const STORAGE_KEY = "loyal.passkey-prf.credentials";

export function loadStoredPasskeys() {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const parsed = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "[]");

    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter(isStoredPasskey);
  } catch {
    return [];
  }
}

export function saveStoredPasskey(passkey: StoredPasskey) {
  const existing = loadStoredPasskeys();
  const next = [
    passkey,
    ...existing.filter((item) => item.id !== passkey.id || item.address !== passkey.address),
  ];

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));

  return next;
}

export function listStoredPasskeysForAddress(address: string) {
  const cleanAddress = address.trim();

  if (!cleanAddress) {
    return [];
  }

  return loadStoredPasskeys().filter((passkey) => passkey.address === cleanAddress);
}

function isStoredPasskey(value: unknown): value is StoredPasskey {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Partial<StoredPasskey>;

  return (
    typeof candidate.id === "string" &&
    typeof candidate.address === "string" &&
    typeof candidate.createdAt === "string" &&
    typeof candidate.label === "string"
  );
}
