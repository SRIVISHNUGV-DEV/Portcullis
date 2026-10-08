import { describe, expect, it } from 'vitest';
import { AbiError, T, bytesToHex, decodeAbi, encodeAbi, hexToBytes } from '../src/abi.js';
import { formatUnits, parseUnits } from '../src/units.js';
import { ALICE } from './helpers.js';

const limits = { maxArrayLength: 64 };
const word = (hex: string) => hex.padStart(64, '0');

function expectAbiError(fn: () => unknown, code: 'MALFORMED' | 'NON_CANONICAL') {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(AbiError);
    expect((e as AbiError).code).toBe(code);
    return;
  }
  throw new Error('expected AbiError');
}

describe('strict ABI codec', () => {
  it('round-trips static, dynamic and nested types', () => {
    const types = [T.address, T.uint256, T.bytes, T.array(T.tuple(T.address, T.uint256, T.bytes))];
    const values = [ALICE, 42n, '0xdeadbeef', [[ALICE, 1n, '0x'], [ALICE, 2n, `0x${'ab'.repeat(40)}`]]];
    expect(decodeAbi(types, encodeAbi(types, values), limits)).toEqual(values);
  });

  it('rejects dirty high bits in an address word', () => {
    const data = hexToBytes(`0x${'ff'.repeat(12)}${ALICE.slice(2)}${word('1')}`);
    expectAbiError(() => decodeAbi([T.address, T.uint256], data, limits), 'NON_CANONICAL');
  });

  it('rejects trailing bytes', () => {
    const data = hexToBytes(`${bytesToHex(encodeAbi([T.address, T.uint256], [ALICE, 1n]))}00`);
    expectAbiError(() => decodeAbi([T.address, T.uint256], data, limits), 'NON_CANONICAL');
  });

  it('rejects truncated calldata', () => {
    const data = hexToBytes(`0x${ALICE.slice(2).padStart(64, '0')}`);
    expectAbiError(() => decodeAbi([T.address, T.uint256], data, limits), 'MALFORMED');
  });

  it('rejects non-boolean values for bool', () => {
    const data = hexToBytes(`0x${word(ALICE.slice(2))}${word('2')}`);
    expectAbiError(() => decodeAbi([T.address, T.bool], data, limits), 'NON_CANONICAL');
  });

  it('rejects out-of-range values for narrow integers', () => {
    const data = hexToBytes(`0x${word('1'.padEnd(13, '0'))}`); // 2^48
    expectAbiError(() => decodeAbi([T.uint48], data, limits), 'NON_CANONICAL');
  });

  it('rejects dynamic offsets that point outside the calldata', () => {
    const data = hexToBytes(`0x${word('ffff')}`);
    expectAbiError(() => decodeAbi([T.bytes], data, limits), 'MALFORMED');
  });

  it('rejects readable but non-standard dynamic offsets', () => {
    // Offset 0x40 instead of 0x20, with a junk word in between.
    const data = hexToBytes(`0x${word('40')}${word('0')}${word('1')}${'ab'.padEnd(64, '0')}`);
    expectAbiError(() => decodeAbi([T.bytes], data, limits), 'NON_CANONICAL');
  });

  it('rejects non-zero padding after dynamic bytes', () => {
    const data = hexToBytes(`0x${word('20')}${word('1')}${'ab'.padEnd(62, '0')}01`);
    expectAbiError(() => decodeAbi([T.bytes], data, limits), 'NON_CANONICAL');
  });

  it('bounds array lengths before allocating', () => {
    const data = hexToBytes(`0x${word('20')}${word('ffffffff')}`);
    expectAbiError(() => decodeAbi([T.array(T.uint256)], data, limits), 'MALFORMED');
  });

  it('rejects odd-length hex', () => {
    expectAbiError(() => hexToBytes('0xabc'), 'MALFORMED');
  });
});

describe('units', () => {
  it('parses and formats exactly', () => {
    expect(parseUnits('1500.25', 6)).toBe(1_500_250_000n);
    expect(formatUnits(1_500_250_000n, 6)).toBe('1,500.25');
    expect(formatUnits(10n ** 18n, 18)).toBe('1');
    expect(formatUnits(1n, 18)).toBe('0.000000000000000001');
  });

  it('rejects excess precision and malformed input', () => {
    expect(() => parseUnits('1.0000001', 6)).toThrow(RangeError);
    expect(() => parseUnits('-1', 6)).toThrow(SyntaxError);
    expect(() => parseUnits('1e6', 6)).toThrow(SyntaxError);
  });
});
