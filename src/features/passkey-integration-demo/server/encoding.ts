import { base64UrlDecode, base64UrlEncode, bytes, type BytesLike } from "@loyal/passkey-sdk";
import { randomBytes as nodeRandomBytes } from "node:crypto";

export function randomBytes(length: number) {
  return nodeRandomBytes(length);
}

export function bytesToBase64Url(value: BytesLike) {
  return base64UrlEncode(bytes(value));
}

export function bytesFromBase64Url(value: string) {
  return base64UrlDecode(value);
}

export function bytesToHex(value: BytesLike) {
  return Buffer.from(bytes(value)).toString("hex");
}

export function bytesFromHex(value: string) {
  if (!/^[0-9a-f]*$/i.test(value) || value.length % 2 !== 0) {
    throw new Error("Expected an even-length hex string.");
  }

  return new Uint8Array(Buffer.from(value, "hex"));
}
