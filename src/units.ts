export const UINT256_MAX = (1n << 256n) - 1n;

/** Convert a decimal string such as "1500.25" into integer base units. Rejects excess precision. */
export function parseUnits(value: string, decimals: number): bigint {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 77) {
    throw new RangeError(`Invalid decimals: ${decimals}`);
  }
  const match = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());
  if (!match) throw new SyntaxError(`Invalid decimal amount: "${value}"`);
  const whole = match[1]!;
  const fraction = match[2] ?? '';
  if (fraction.length > decimals) {
    throw new RangeError(`"${value}" has more than ${decimals} decimal places`);
  }
  const result = BigInt(whole + fraction.padEnd(decimals, '0'));
  if (result > UINT256_MAX) throw new RangeError(`"${value}" exceeds uint256`);
  return result;
}

/** Exact base-unit formatting with thousands separators and trimmed trailing zeros. */
export function formatUnits(amount: bigint, decimals: number): string {
  const negative = amount < 0n;
  const abs = negative ? -amount : amount;
  const base = 10n ** BigInt(decimals);
  const whole = (abs / base).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = decimals > 0 ? (abs % base).toString().padStart(decimals, '0').replace(/0+$/, '') : '';
  return `${negative ? '-' : ''}${whole}${fraction ? `.${fraction}` : ''}`;
}
