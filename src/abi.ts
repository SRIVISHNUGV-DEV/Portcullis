// Minimal strict Solidity ABI codec for the argument types the firewall inspects.
//
// Decoding is canonical-only: after decoding, the values are re-encoded with the
// standard encoder and must reproduce the input byte-for-byte. This rejects dirty
// address/integer high bits, non-0/1 booleans, trailing bytes, overlapping or
// non-standard dynamic offsets and non-zero padding — encodings a token contract may
// still accept but that an off-chain decoder could interpret differently.

export type AbiType =
  | { readonly kind: 'address' }
  | { readonly kind: 'uint'; readonly bits: number }
  | { readonly kind: 'bool' }
  | { readonly kind: 'bytes32' }
  | { readonly kind: 'bytes' }
  | { readonly kind: 'tuple'; readonly components: readonly AbiType[] }
  | { readonly kind: 'array'; readonly item: AbiType };

export type AbiValue = string | bigint | boolean | readonly AbiValue[];

export type AbiErrorCode = 'MALFORMED' | 'NON_CANONICAL';

export class AbiError extends Error {
  constructor(readonly code: AbiErrorCode, message: string) {
    super(message);
    this.name = 'AbiError';
  }
}

export const T = {
  address: { kind: 'address' },
  uint256: { kind: 'uint', bits: 256 },
  uint160: { kind: 'uint', bits: 160 },
  uint48: { kind: 'uint', bits: 48 },
  uint8: { kind: 'uint', bits: 8 },
  bool: { kind: 'bool' },
  bytes32: { kind: 'bytes32' },
  bytes: { kind: 'bytes' },
  tuple: (...components: AbiType[]): AbiType => ({ kind: 'tuple', components }),
  array: (item: AbiType): AbiType => ({ kind: 'array', item }),
} as const satisfies Record<string, AbiType | ((...args: never[]) => AbiType)>;

const WORD = 32;

export interface DecodeLimits {
  /** Maximum element count of any dynamic array. */
  readonly maxArrayLength: number;
}

const HEX_RE = /^0x(?:[0-9a-fA-F]{2})*$/;

export function isHex(value: string): boolean {
  return HEX_RE.test(value);
}

export function hexToBytes(hex: string): Uint8Array {
  if (!isHex(hex)) throw new AbiError('MALFORMED', 'Calldata is not even-length 0x-prefixed hex');
  return Uint8Array.from(Buffer.from(hex.slice(2), 'hex'));
}

export function bytesToHex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex')}`;
}

function isDynamic(t: AbiType): boolean {
  if (t.kind === 'bytes' || t.kind === 'array') return true;
  if (t.kind === 'tuple') return t.components.some(isDynamic);
  return false;
}

function headSize(t: AbiType): number {
  if (isDynamic(t)) return WORD;
  if (t.kind === 'tuple') return t.components.reduce((n, c) => n + headSize(c), 0);
  return WORD;
}

function readWord(buf: Uint8Array, at: number): bigint {
  if (at < 0 || at + WORD > buf.length) {
    throw new AbiError('MALFORMED', `ABI read out of bounds at byte ${at}`);
  }
  let v = 0n;
  for (let i = at; i < at + WORD; i++) v = (v << 8n) | BigInt(buf[i]!);
  return v;
}

function toIndex(v: bigint, limit: number, what: string): number {
  if (v > BigInt(limit)) throw new AbiError('MALFORMED', `${what} ${v} exceeds calldata bounds`);
  return Number(v);
}

function decodeValue(t: AbiType, buf: Uint8Array, at: number, limits: DecodeLimits): AbiValue {
  switch (t.kind) {
    case 'address': {
      // Masked here; dirty high bits are caught by the canonical re-encode comparison.
      const v = readWord(buf, at) & ((1n << 160n) - 1n);
      return `0x${v.toString(16).padStart(40, '0')}`;
    }
    case 'uint': {
      const v = readWord(buf, at);
      return t.bits === 256 ? v : v & ((1n << BigInt(t.bits)) - 1n);
    }
    case 'bool':
      return readWord(buf, at) !== 0n;
    case 'bytes32':
      return `0x${readWord(buf, at).toString(16).padStart(64, '0')}`;
    case 'bytes': {
      const len = toIndex(readWord(buf, at), buf.length, 'Byte length');
      const start = at + WORD;
      if (start + len > buf.length) throw new AbiError('MALFORMED', 'Dynamic bytes exceed calldata bounds');
      return bytesToHex(buf.subarray(start, start + len));
    }
    case 'array': {
      const len = toIndex(readWord(buf, at), buf.length, 'Array length');
      if (len > limits.maxArrayLength) {
        throw new AbiError('MALFORMED', `Array length ${len} exceeds limit ${limits.maxArrayLength}`);
      }
      return decodeSequence(Array.from({ length: len }, () => t.item), buf, at + WORD, limits);
    }
    case 'tuple':
      return decodeSequence(t.components, buf, at, limits);
  }
}

function decodeSequence(types: readonly AbiType[], buf: Uint8Array, base: number, limits: DecodeLimits): AbiValue[] {
  const out: AbiValue[] = [];
  let cursor = base;
  for (const t of types) {
    if (isDynamic(t)) {
      const offset = toIndex(readWord(buf, cursor), buf.length, 'Dynamic offset');
      out.push(decodeValue(t, buf, base + offset, limits));
    } else {
      out.push(decodeValue(t, buf, cursor, limits));
    }
    cursor += headSize(t);
  }
  return out;
}

function word(v: bigint): Uint8Array {
  const out = new Uint8Array(WORD);
  let x = v;
  for (let i = WORD - 1; i >= 0 && x > 0n; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function encodeValue(t: AbiType, v: AbiValue): Uint8Array {
  switch (t.kind) {
    case 'address':
    case 'bytes32':
      return word(BigInt(v as string));
    case 'uint':
      return word(v as bigint);
    case 'bool':
      return word(v ? 1n : 0n);
    case 'bytes': {
      const data = hexToBytes(v as string);
      const padded = new Uint8Array(Math.ceil(data.length / WORD) * WORD);
      padded.set(data);
      return concat([word(BigInt(data.length)), padded]);
    }
    case 'array': {
      const items = v as readonly AbiValue[];
      return concat([word(BigInt(items.length)), encodeSequence(items.map(() => t.item), items)]);
    }
    case 'tuple':
      return encodeSequence(t.components, v as readonly AbiValue[]);
  }
}

function encodeSequence(types: readonly AbiType[], values: readonly AbiValue[]): Uint8Array {
  const heads: Uint8Array[] = [];
  const tails: Uint8Array[] = [];
  let tailOffset = types.reduce((n, t) => n + headSize(t), 0);
  types.forEach((t, i) => {
    const encoded = encodeValue(t, values[i]!);
    if (isDynamic(t)) {
      heads.push(word(BigInt(tailOffset)));
      tails.push(encoded);
      tailOffset += encoded.length;
    } else {
      heads.push(encoded);
    }
  });
  return concat([...heads, ...tails]);
}

export function encodeAbi(types: readonly AbiType[], values: readonly AbiValue[]): Uint8Array {
  return encodeSequence(types, values);
}

/**
 * Decode ABI-encoded arguments (without the 4-byte selector). Throws AbiError with
 * `MALFORMED` for unreadable input and `NON_CANONICAL` for readable but
 * non-standard encodings.
 */
export function decodeAbi(types: readonly AbiType[], args: Uint8Array, limits: DecodeLimits): AbiValue[] {
  const values = decodeSequence(types, args, 0, limits);
  const canonical = encodeSequence(types, values);
  if (canonical.length !== args.length || !canonical.every((b, i) => b === args[i])) {
    throw new AbiError(
      'NON_CANONICAL',
      'Calldata is not canonically ABI-encoded (dirty padding, trailing bytes or non-standard offsets)',
    );
  }
  return values;
}
