import { Keypair } from "@solana/web3.js";
import {
  arrayBuffer,
  bytes,
  base64UrlDecode,
  base64UrlEncode,
  concatBytes,
  sha256,
  utf8,
  type BytesLike,
} from "./bytes";
import type { CompressedP256PublicKey } from "./addresses";

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

type AttestationResponseWithPublicKey = AuthenticatorAttestationResponse & {
  getPublicKey?: () => ArrayBuffer | null;
};

export type PasskeyCredential = {
  credentialId: Uint8Array;
  credentialIdBase64Url: string;
  credentialIdHash: Uint8Array;
  passkeyPublicKey: CompressedP256PublicKey;
  prfEnabled: boolean | null;
  transports?: AuthenticatorTransport[];
};

export type PasskeyAssertion = {
  credentialId: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  signature: Uint8Array;
  prfFirst: Uint8Array | null;
};

export type PrfAuthority = {
  keypair: Keypair;
  publicKey: Keypair["publicKey"];
  prfOutput: Uint8Array;
};

export function isPasskeySmartAccountSupported() {
  return (
    typeof window !== "undefined" &&
    "PublicKeyCredential" in window &&
    typeof navigator.credentials?.create === "function" &&
    typeof navigator.credentials?.get === "function"
  );
}

export async function createPasskeyCredential({
  userName,
  displayName = userName,
  relyingPartyName = "Loyal",
  userId,
  creationChallenge,
  prfSalt,
}: {
  userName: string;
  displayName?: string;
  relyingPartyName?: string;
  userId?: BytesLike;
  creationChallenge?: BytesLike;
  prfSalt?: BytesLike;
}) {
  assertWebAuthn();

  const challenge = creationChallenge ? bytes(creationChallenge) : crypto.getRandomValues(new Uint8Array(32));
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: arrayBuffer(challenge),
      rp: { name: relyingPartyName },
      user: {
        id: arrayBuffer(userId ? bytes(userId) : await sha256(utf8(`loyal-passkey-user:${userName}`))),
        name: userName,
        displayName,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      attestation: "none",
      extensions: prfSalt
        ? ({
            prf: {
              eval: {
                first: arrayBuffer(prfSalt),
              },
            },
          } as AuthenticationExtensionsClientInputs)
        : undefined,
    },
  })) as PublicKeyCredentialWithResponse<AuthenticatorAttestationResponse> | null;

  if (!credential) {
    throw new Error("Passkey creation was cancelled.");
  }

  const extensionResults = credential.getClientExtensionResults() as PrfCreationResults;
  const credentialId = bytes(credential.rawId);
  const response = credential.response as AttestationResponseWithPublicKey;

  return {
    credentialId,
    credentialIdBase64Url: base64UrlEncode(credentialId),
    credentialIdHash: await sha256(credentialId),
    passkeyPublicKey: await compressedP256PublicKeyFromAttestation(response),
    prfEnabled: extensionResults.prf?.enabled ?? null,
    transports: credential.response.getTransports?.() as AuthenticatorTransport[] | undefined,
  } satisfies PasskeyCredential;
}

export async function getPasskeyAssertion({
  credentialId,
  challenge,
  prfSalt,
  transports,
}: {
  credentialId: BytesLike | string;
  challenge: BytesLike;
  prfSalt?: BytesLike;
  transports?: AuthenticatorTransport[];
}) {
  assertWebAuthn();

  const credentialIdBytes = typeof credentialId === "string" ? base64UrlDecode(credentialId) : bytes(credentialId);
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: arrayBuffer(challenge),
      allowCredentials: [
        {
          id: arrayBuffer(credentialIdBytes),
          type: "public-key",
          transports,
        },
      ],
      userVerification: "required",
      extensions: prfSalt
        ? ({
            prf: {
              eval: {
                first: arrayBuffer(prfSalt),
              },
            },
          } as AuthenticationExtensionsClientInputs)
        : undefined,
    },
  })) as PublicKeyCredentialWithResponse<AuthenticatorAssertionResponse> | null;

  if (!assertion) {
    throw new Error("Passkey assertion was cancelled.");
  }

  const extensionResults = assertion.getClientExtensionResults() as PrfGetResults;
  const prfFirst = extensionResults.prf?.results?.first;

  return {
    credentialId: bytes(assertion.rawId),
    authenticatorData: bytes(assertion.response.authenticatorData),
    clientDataJson: bytes(assertion.response.clientDataJSON),
    signature: derEcdsaSignatureToCompact(bytes(assertion.response.signature)),
    prfFirst: prfFirst ? bytes(prfFirst) : null,
  } satisfies PasskeyAssertion;
}

export async function derivePrfAuthority({
  credentialId,
  prfSalt,
  transports,
}: {
  credentialId: BytesLike | string;
  prfSalt: BytesLike;
  transports?: AuthenticatorTransport[];
}) {
  const assertion = await getPasskeyAssertion({
    credentialId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    prfSalt,
    transports,
  });

  if (!assertion.prfFirst) {
    throw new Error("This authenticator did not return a PRF output.");
  }

  const keypair = Keypair.fromSeed(assertion.prfFirst);

  return {
    keypair,
    publicKey: keypair.publicKey,
    prfOutput: assertion.prfFirst,
  } satisfies PrfAuthority;
}

export async function defaultPrfSalt(credentialIdHash: BytesLike) {
  return sha256(concatBytes([utf8("LOYAL_PASSKEY_PRF_AUTHORITY_V1"), bytes(credentialIdHash)]));
}

export async function webauthnSignedMessage(assertion: Pick<PasskeyAssertion, "authenticatorData" | "clientDataJson">) {
  return concatBytes([assertion.authenticatorData, await sha256(assertion.clientDataJson)]);
}

async function compressedP256PublicKeyFromAttestation(response: AttestationResponseWithPublicKey) {
  const spki = response.getPublicKey?.();

  if (!spki) {
    throw new Error("This browser did not expose the passkey public key.");
  }

  const key = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const raw = bytes(await crypto.subtle.exportKey("raw", key));

  if (raw.length !== 65 || raw[0] !== 4) {
    throw new Error("Expected an uncompressed P-256 public key.");
  }

  return {
    prefix: raw[64] % 2 === 0 ? 2 : 3,
    x: raw.slice(1, 33),
  } satisfies CompressedP256PublicKey;
}

function derEcdsaSignatureToCompact(signature: Uint8Array) {
  if (signature[0] !== 0x30) {
    throw new Error("Expected a DER-encoded ECDSA signature.");
  }

  let offset = 2;

  if (signature[1] & 0x80) {
    offset += signature[1] & 0x7f;
  }

  const r = readDerInteger(signature, offset);

  offset = r.nextOffset;
  const s = readDerInteger(signature, offset);

  return concatBytes([leftPad32(r.value), leftPad32(s.value)]);
}

function readDerInteger(signature: Uint8Array, offset: number) {
  if (signature[offset] !== 0x02) {
    throw new Error("Invalid DER ECDSA integer.");
  }

  const length = signature[offset + 1];
  const start = offset + 2;
  const end = start + length;

  return {
    value: signature.slice(start, end),
    nextOffset: end,
  };
}

function leftPad32(value: Uint8Array) {
  const trimmed = value[0] === 0 ? value.slice(1) : value;

  if (trimmed.length > 32) {
    throw new Error("Invalid ECDSA scalar length.");
  }

  const output = new Uint8Array(32);

  output.set(trimmed, 32 - trimmed.length);

  return output;
}

function assertWebAuthn() {
  if (!isPasskeySmartAccountSupported()) {
    throw new Error("This browser does not support the WebAuthn APIs required for passkey smart accounts.");
  }
}
