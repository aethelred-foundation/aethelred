/**
 * Encoding Utilities
 */

/**
 * Encode string to base64
 */
export function toBase64(data: string | Buffer): string {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return buffer.toString('base64');
}

/**
 * Decode base64 to string
 */
export function fromBase64(encoded: string): string {
  return Buffer.from(encoded, 'base64').toString('utf-8');
}

/**
 * Decode base64 to buffer
 */
export function fromBase64ToBuffer(encoded: string): Buffer {
  return Buffer.from(encoded, 'base64');
}

/**
 * Encode to hex
 */
export function toHex(data: string | Buffer): string {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return buffer.toString('hex');
}

/**
 * Decode from hex
 */
export function fromHex(encoded: string): Buffer {
  return Buffer.from(encoded, 'hex');
}

/**
 * Encode string to URL-safe base64
 */
export function toBase64Url(data: string | Buffer): string {
  return toBase64(data)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode URL-safe base64 to string
 */
export function fromBase64Url(encoded: string): string {
  let base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  return fromBase64(base64);
}

/**
 * Encode Bech32 address
 */
export function toBech32(prefix: string, data: Buffer): string {
  // Simplified Bech32 encoding (use @cosmjs/encoding in production)
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const dataWords = convertBits(Array.from(data), 8, 5, true);
  const checksum = createChecksum(prefix, dataWords);
  return prefix + '1' + dataWords.concat(checksum).map((d) => CHARSET.charAt(d)).join('');
}

/**
 * Decode Bech32 address
 */
export function fromBech32(address: string): { prefix: string; data: Buffer } {
  const pos = address.lastIndexOf('1');
  if (pos < 1) {
    throw new Error('Invalid bech32 address');
  }

  const prefix = address.slice(0, pos);
  const dataStr = address.slice(pos + 1);
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  const dataWords = Array.from(dataStr).map((c) => {
    const idx = CHARSET.indexOf(c);
    if (idx === -1) throw new Error('Invalid character');
    return idx;
  });

  // Remove checksum (last 6 chars)
  const words = dataWords.slice(0, -6);
  const data = convertBits(words, 5, 8, false);

  return {
    prefix,
    data: Buffer.from(data),
  };
}

/**
 * Validate Bech32 address
 */
export function isValidBech32(address: string, expectedPrefix?: string): boolean {
  try {
    const { prefix } = fromBech32(address);
    if (expectedPrefix && prefix !== expectedPrefix) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Encode to CBOR (simplified)
 */
export function toCBOR(data: unknown): Buffer {
  // Simplified CBOR encoding for common types
  // Use cbor package for full implementation
  return Buffer.from(JSON.stringify(data));
}

/**
 * Decode from CBOR (simplified)
 */
export function fromCBOR<T>(encoded: Buffer): T {
  return JSON.parse(encoded.toString()) as T;
}

/**
 * Canonicalize JSON for consistent hashing
 */
export function canonicalizeJSON(obj: unknown): string {
  return JSON.stringify(obj, (key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value)
        .sort()
        .reduce((result: Record<string, unknown>, key) => {
          result[key] = value[key];
          return result;
        }, {});
    }
    return value;
  });
}

/**
 * Encode Uint8Array to string
 */
export function uint8ArrayToString(arr: Uint8Array): string {
  return Buffer.from(arr).toString('utf-8');
}

/**
 * Encode string to Uint8Array
 */
export function stringToUint8Array(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'utf-8'));
}

/**
 * Convert big number to bytes
 */
export function bigIntToBytes(num: bigint, length: number = 32): Buffer {
  const hex = num.toString(16).padStart(length * 2, '0');
  return Buffer.from(hex, 'hex');
}

/**
 * Convert bytes to big number
 */
export function bytesToBigInt(bytes: Buffer): bigint {
  return BigInt('0x' + bytes.toString('hex'));
}

// Helper functions

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const result: number[] = [];
  const maxv = (1 << toBits) - 1;

  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error('Invalid padding');
  }

  return result;
}

function createChecksum(prefix: string, data: number[]): number[] {
  const values = [...prefix.split('').map((c) => c.charCodeAt(0) >> 5)];
  values.push(0);
  values.push(...prefix.split('').map((c) => c.charCodeAt(0) & 31));
  values.push(...data);
  values.push(0, 0, 0, 0, 0, 0);

  const polymod = bech32Polymod(values) ^ 1;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> (5 * (5 - i))) & 31);
  }
  return checksum;
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) {
        chk ^= GEN[i];
      }
    }
  }
  return chk;
}
