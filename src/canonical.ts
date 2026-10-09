import { createHash } from 'node:crypto';

/** Deterministic JSON: sorted object keys, bigint rendered as a decimal string, undefined omitted. */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('Non-finite number in canonical JSON');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        let out = '[';
        for (let i = 0; i < value.length; i++) {
          if (i > 0) out += ',';
          out += value[i] === undefined ? 'null' : canonicalJson(value[i]);
        }
        return `${out}]`;
      }
      if (value instanceof Set || value instanceof Map) throw new TypeError('Set/Map not supported in canonical JSON');
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      let out = '{';
      let first = true;
      for (const k of keys) {
        const v = obj[k];
        if (v === undefined) continue;
        if (!first) out += ',';
        first = false;
        out += `${JSON.stringify(k)}:${canonicalJson(v)}`;
      }
      return `${out}}`;
    }
    default:
      throw new TypeError(`Unsupported value in canonical JSON: ${typeof value}`);
  }
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export function digest(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

/** Convert bigint fields to decimal strings so the value is plain-JSON serializable. */
export function toJsonSafe<T>(value: T): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(toJsonSafe);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = toJsonSafe(v);
    return out;
  }
  return value;
}

export function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) deepFreeze(v);
  }
  return value;
}
