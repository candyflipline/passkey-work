export type StoredPasskey = {
  id: string;
  address: string;
  createdAt: string;
  label: string;
  prfEnabled: boolean | null;
  transports?: AuthenticatorTransport[];
};

type PrfCreationResults = AuthenticationExtensionsClientOutputs & {
  prf?: {
    enabled?: boolean;
  };
};

type PrfGetResults = AuthenticationExtensionsClientOutputs & {
  prf?: {
    results?: {
      first?: ArrayBuffer;
    };
  };
};

type PublicKeyCredentialWithResponse<TResponse extends AuthenticatorResponse> =
  PublicKeyCredential & {
    response: TResponse;
  };

export function isWebAuthnSupported() {
  return (
    typeof window !== "undefined" &&
    "PublicKeyCredential" in window &&
    typeof navigator.credentials?.create === "function" &&
    typeof navigator.credentials?.get === "function"
  );
}

export function normalizeAddress(value: string) {
  return value.trim();
}

export function credentialIdToBase64Url(id: ArrayBuffer) {
  return base64UrlEncode(new Uint8Array(id));
}

export function credentialIdFromBase64Url(value: string) {
  return base64UrlDecode(value);
}

export async function createPasskeyForAddress(address: string) {
  const cleanAddress = normalizeAddress(address);

  if (!cleanAddress) {
    throw new Error("Enter an address before creating a passkey.");
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = await sha256Bytes(`loyal-passkey-user:${cleanAddress}`);
  const prfSalt = await prfSaltForAddress(cleanAddress);

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: "Loyal Passkey Work",
      },
      user: {
        id: userId,
        name: cleanAddress,
        displayName: cleanAddress,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred",
      },
      attestation: "none",
      extensions: {
        prf: {
          eval: {
            first: prfSalt,
          },
        },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredentialWithResponse<AuthenticatorAttestationResponse> | null;

  if (!credential) {
    throw new Error("Passkey creation was cancelled.");
  }

  const extensionResults = credential.getClientExtensionResults() as PrfCreationResults;
  const transports = credential.response.getTransports?.() as
    | AuthenticatorTransport[]
    | undefined;

  return {
    id: credentialIdToBase64Url(credential.rawId),
    address: cleanAddress,
    createdAt: new Date().toISOString(),
    label: labelForCredential(credential.id),
    prfEnabled: extensionResults.prf?.enabled ?? null,
    transports,
  } satisfies StoredPasskey;
}

export async function findExistingPasskeyForAddress(address: string) {
  const cleanAddress = normalizeAddress(address);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = cleanAddress ? await prfSaltForAddress(cleanAddress) : null;

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      userVerification: "preferred",
      ...(prfSalt
        ? {
            extensions: ({
              prf: {
                eval: {
                  first: prfSalt,
                },
              },
            } as AuthenticationExtensionsClientInputs),
          }
        : {}),
    },
  })) as PublicKeyCredentialWithResponse<AuthenticatorAssertionResponse> | null;

  if (!assertion) {
    throw new Error("Passkey lookup was cancelled.");
  }

  const extensionResults = assertion.getClientExtensionResults() as PrfGetResults;
  const prfFirst = extensionResults.prf?.results?.first;
  const credentialId = credentialIdToBase64Url(assertion.rawId);

  return {
    passkey: {
      id: credentialId,
      address: cleanAddress,
      createdAt: new Date().toISOString(),
      label: labelForCredential(assertion.id),
      prfEnabled: prfFirst ? true : null,
    } satisfies StoredPasskey,
    prfFirst: prfFirst ? base64UrlEncode(new Uint8Array(prfFirst)) : null,
  };
}

export async function testPasskeyPrf(passkey: StoredPasskey) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = await prfSaltForAddress(passkey.address);

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [
        {
          id: credentialIdFromBase64Url(passkey.id),
          type: "public-key",
          transports: passkey.transports,
        },
      ],
      userVerification: "preferred",
      extensions: {
        prf: {
          eval: {
            first: prfSalt,
          },
        },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredentialWithResponse<AuthenticatorAssertionResponse> | null;

  if (!assertion) {
    throw new Error("Passkey check was cancelled.");
  }

  const extensionResults = assertion.getClientExtensionResults() as PrfGetResults;
  const prfFirst = extensionResults.prf?.results?.first;

  return {
    credentialId: credentialIdToBase64Url(assertion.rawId),
    prfFirst: prfFirst ? base64UrlEncode(new Uint8Array(prfFirst)) : null,
  };
}

async function prfSaltForAddress(address: string) {
  return sha256Bytes(`loyal-passkey-prf:${address}`);
}

async function sha256Bytes(value: string) {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);

  return new Uint8Array(digest);
}

function labelForCredential(id: string) {
  return `Passkey ${id.slice(0, 6)}`;
}

function base64UrlEncode(bytes: Uint8Array) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlDecode(value: string) {
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}
