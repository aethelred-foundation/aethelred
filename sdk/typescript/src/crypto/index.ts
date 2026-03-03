/**
 * Cryptographic utilities for Aethelred SDK.
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export function sha256(data: Uint8Array | string): Uint8Array {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return nobleSha256(input);
}

export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256(data));
}

export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function fromHex(hex: string): Uint8Array {
  return hexToBytes(hex);
}

export { bytesToHex, hexToBytes };
