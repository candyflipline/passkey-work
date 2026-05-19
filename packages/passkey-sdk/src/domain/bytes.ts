import { PublicKey } from "@solana/web3.js";

export type BytesLike = Uint8Array | ArrayBuffer | readonly number[];

const textEncoder = new TextEncoder();

export function bytes(value: BytesLike) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  return new Uint8Array(value);
}

export function utf8(value: string) {
  return textEncoder.encode(value);
}

export function publicKeyBytes(value: PublicKey | string) {
  return new PublicKey(value).toBytes();
}

export function concatBytes(values: BytesLike[]) {
  const totalLength = values.reduce((total, value) => total + bytes(value).length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const value of values) {
    const item = bytes(value);

    output.set(item, offset);
    offset += item.length;
  }

  return output;
}

export async function sha256(value: BytesLike) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBuffer(value)));
}

export async function hashv(values: BytesLike[]) {
  return sha256(concatBytes(values));
}

export function base64UrlEncode(value: BytesLike) {
  const input = bytes(value);
  let binary = "";

  for (const byte of input) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function base64UrlDecode(value: string) {
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const output = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    output[index] = binary.charCodeAt(index);
  }

  return output;
}

export function littleEndianU64(value: bigint | number) {
  const output = new Uint8Array(8);
  const view = new DataView(output.buffer);

  view.setBigUint64(0, BigInt(value), true);

  return output;
}

export function littleEndianI64(value: bigint | number) {
  const output = new Uint8Array(8);
  const view = new DataView(output.buffer);

  view.setBigInt64(0, BigInt(value), true);

  return output;
}

export function littleEndianU128(value: bigint | number) {
  let remaining = BigInt(value);
  const output = new Uint8Array(16);

  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number(remaining & BigInt(255));
    remaining >>= BigInt(8);
  }

  return output;
}

export function fixedBytes(value: BytesLike, length: number, label: string) {
  const input = bytes(value);

  if (input.length !== length) {
    throw new Error(`${label} must be ${length} bytes.`);
  }

  return input;
}

export function arrayBuffer(value: BytesLike) {
  const input = bytes(value);

  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

export function readU64Le(data: Uint8Array, offset: number) {
  return new DataView(data.buffer, data.byteOffset + offset, 8).getBigUint64(0, true);
}
