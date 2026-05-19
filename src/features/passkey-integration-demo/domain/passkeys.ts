import {
  createPasskeyCredential,
  defaultPrfSalt,
  derivePrfAuthority,
  getPasskeyAssertion,
  isPasskeySmartAccountSupported,
  type PasskeyAssertion,
} from "@loyal/passkey-sdk/browser";
import {
  beginPasskeyCreate,
  beginPasskeyLogin,
  completePasskeyLogin,
  completePasskeyRegistration,
  preparePasskeyRegistration,
} from "./api";
import { bytesFromBase64Url, bytesToBase64Url, bytesToHex } from "./encoding";
import { saveStoredDemoPasskey, type StoredDemoPasskey } from "./local-passkeys";
import type { SerializedPasskeyAssertion } from "../types";

export { isPasskeySmartAccountSupported };

export async function createPasskeyThroughBackend() {
  const begin = await beginPasskeyCreate();
  const credential = await createPasskeyCredential({
    userName: begin.userName,
    displayName: begin.displayName,
    relyingPartyName: begin.relyingPartyName,
    creationChallenge: bytesFromBase64Url(begin.creationChallenge),
  });
  const prfSalt = await defaultPrfSalt(credential.credentialIdHash);
  const authority = await derivePrfAuthority({
    credentialId: credential.credentialId,
    prfSalt,
    transports: credential.transports,
  });
  const passkeyPublicKey = {
    prefix: credential.passkeyPublicKey.prefix,
    x: bytesToHex(credential.passkeyPublicKey.x),
  };
  const prepared = await preparePasskeyRegistration({
    credentialIdHash: bytesToBase64Url(credential.credentialIdHash),
    passkeyPublicKey,
    ed25519Authority: authority.publicKey.toBase58(),
  });
  const assertion = await getPasskeyAssertion({
    credentialId: credential.credentialId,
    challenge: bytesFromBase64Url(prepared.registrationChallenge),
    transports: credential.transports,
  });
  const completed = await completePasskeyRegistration({
    registrationId: prepared.registrationId,
    assertion: serializeAssertion(assertion),
  });
  const storedPasskey = {
    label: `Passkey ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`,
    credentialId: credential.credentialIdBase64Url,
    credentialIdHash: bytesToBase64Url(credential.credentialIdHash),
    passkeyPublicKey,
    authority: authority.publicKey.toBase58(),
    createdAt: new Date().toISOString(),
  } satisfies StoredDemoPasskey;

  saveStoredDemoPasskey(storedPasskey);

  return {
    ...completed,
    storedPasskey,
  };
}

export async function loginWithStoredPasskey(passkey: StoredDemoPasskey) {
  const begin = await beginPasskeyLogin();
  const assertion = await getPasskeyAssertion({
    credentialId: passkey.credentialId,
    challenge: bytesFromBase64Url(begin.loginChallenge),
  });

  return completePasskeyLogin({
    loginId: begin.loginId,
    credentialIdHash: passkey.credentialIdHash,
    passkeyPublicKey: passkey.passkeyPublicKey,
    assertion: serializeAssertion(assertion),
  });
}

function serializeAssertion(assertion: PasskeyAssertion) {
  return {
    credentialId: bytesToBase64Url(assertion.credentialId),
    authenticatorData: bytesToBase64Url(assertion.authenticatorData),
    clientDataJson: bytesToBase64Url(assertion.clientDataJson),
    signature: bytesToBase64Url(assertion.signature),
  } satisfies SerializedPasskeyAssertion;
}
