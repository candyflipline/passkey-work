import { base64UrlDecode, base64UrlEncode, bytes, type BytesLike } from "@loyal/passkey-sdk/browser";

export function bytesToBase64Url(value: BytesLike) {
  return base64UrlEncode(bytes(value));
}

export function bytesFromBase64Url(value: string) {
  return base64UrlDecode(value);
}

export function bytesToHex(value: BytesLike) {
  return Array.from(bytes(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
