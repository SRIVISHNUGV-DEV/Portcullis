import { z } from 'zod';
import { UINT256_MAX } from './units.js';

// ── primitives ──────────────────────────────────────────────────────────────

export const AddressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, 'Expected a 20-byte 0x-prefixed hex address')
  .transform((a) => a.toLowerCase());

export const SelectorSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{8}$/, 'Expected a 4-byte 0x-prefixed function selector')
  .transform((s) => s.toLowerCase());

/** Hard ceiling applied before policy limits so oversized payloads are rejected cheaply. */
const MAX_HEX_CHARS = 2 + 2 * 1_048_576;

export const HexDataSchema = z
  .string()
  .max(MAX_HEX_CHARS, 'Calldata exceeds 1 MiB')
  .regex(/^0x(?:[0-9a-fA-F]{2})*$/, 'Expected even-length 0x-prefixed hex data')
  .transform((h) => h.toLowerCase());

/** Integer amount in base units: bigint, decimal string, 0x hex string or safe integer. */
export const AmountSchema = z
  .union([
    z.bigint(),
    z.string().regex(/^(?:0|[1-9]\d*)$/, 'Expected a base-unit decimal integer string'),
    z.string().regex(/^0x[0-9a-fA-F]{1,64}$/, 'Expected a 0x hex integer'),
    z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  ])
  .transform((v) => BigInt(v))
  .refine((v) => v >= 0n && v <= UINT256_MAX, 'Amount must be within uint256');

export const ChainIdSchema = z
  .union([
    z.number().int().positive(),
    z.bigint().positive(),
    z.string().regex(/^(?:[1-9]\d*|0x[0-9a-fA-F]+)$/, 'Expected a chain ID'),
  ])
  .transform((v) => Number(v))
  .refine((v) => Number.isSafeInteger(v) && v > 0, 'Chain ID must be a positive safe integer');

export const ModeSchema = z.enum(['block', 'requireApproval']);
export type Mode = z.output<typeof ModeSchema>;

// ── transaction requests ────────────────────────────────────────────────────

/** A wallet-SDK call object. Unknown fields (gas, nonce, …) are ignored. */
export const CallInputSchema = z.object({
  to: AddressSchema.nullish(),
  value: AmountSchema.optional(),
  data: HexDataSchema.optional(),
});

export const TransactionRequestSchema = z
  .object({
    chainId: ChainIdSchema,
    /** The agent wallet that will execute the call(s). */
    from: AddressSchema,
    to: AddressSchema.nullish(),
    value: AmountSchema.optional(),
    data: HexDataSchema.optional(),
    /** Batched calls executed atomically by a smart wallet (EIP-5792 `wallet_sendCalls`, Safe MultiSend, …). */
    calls: z.array(CallInputSchema).min(1).max(256).optional(),
  })
  .superRefine((r, ctx) => {
    if (r.calls && (r.to !== undefined || r.value !== undefined || r.data !== undefined)) {
      ctx.addIssue({ code: 'custom', message: 'Provide either `calls` or a single `to`/`value`/`data`, not both' });
    }
  })
  .transform((r) => ({
    chainId: r.chainId,
    from: r.from,
    calls: (r.calls ?? [{ to: r.to, value: r.value, data: r.data }]).map((c) => ({
      to: c.to ?? null,
      value: c.value ?? 0n,
      data: c.data ?? '0x',
    })),
  }));

export type TransactionRequestInput = z.input<typeof TransactionRequestSchema>;
export type NormalizedRequest = z.output<typeof TransactionRequestSchema>;
export type NormalizedCall = NormalizedRequest['calls'][number];

// ── policy ──────────────────────────────────────────────────────────────────

export const TokenRuleSchema = z.strictObject({
  address: AddressSchema,
  symbol: z.string().min(1).max(32),
  decimals: z.number().int().min(0).max(77),
  /** Maximum moved or approved by one request (summed across a batch). */
  perTransactionMax: AmountSchema,
  /** Maximum moved or approved across the whole session, including pending reservations. */
  sessionMax: AmountSchema,
  /** Amounts above this (but within caps) need a human approval. */
  requireApprovalAbove: AmountSchema.optional(),
  /** Largest single allowance grant. Defaults to `perTransactionMax`. */
  maxApproval: AmountSchema.optional(),
  /** Extra non-transfer functions allowed on this token, e.g. WETH `deposit()`/`withdraw(uint256)`. */
  allowedFunctions: z.array(SelectorSchema).default([]),
});

export const NftRuleSchema = z.strictObject({
  address: AddressSchema,
  name: z.string().min(1).max(64),
  standard: z.enum(['erc721', 'erc1155']),
  /** When false, transfers out of this collection require approval. */
  allowTransfers: z.boolean().default(false),
});

export const ProtocolRuleSchema = z.strictObject({
  name: z.string().min(1).max(64),
  address: AddressSchema,
  /** Allowed function selectors. Omit to allow any function on this contract. */
  selectors: z.array(SelectorSchema).min(1).optional(),
  /** Maximum native value per call to this contract. */
  maxNativeValue: AmountSchema.optional(),
});

export const PolicySchema = z
  .strictObject({
    version: z.literal(1),
    name: z.string().min(1).max(100).optional(),
    chainIds: z.array(ChainIdSchema).min(1),
    native: z.strictObject({
      symbol: z.string().min(1).max(16).default('ETH'),
      perTransactionMax: AmountSchema,
      sessionMax: AmountSchema,
      requireApprovalAbove: AmountSchema.optional(),
    }),
    tokens: z.array(TokenRuleSchema).default([]),
    nfts: z.array(NftRuleSchema).default([]),
    protocols: z.array(ProtocolRuleSchema).default([]),
    approvals: z
      .strictObject({
        /** Trusted spenders/operators. Allowlisted protocol addresses are trusted spenders too. */
        spenders: z.array(AddressSchema).default([]),
        unknownSpender: ModeSchema.default('requireApproval'),
        /** `setApprovalForAll(operator, true)` to an untrusted operator. */
        operatorApprovals: ModeSchema.default('block'),
      })
      .prefault({}),
    recipients: z
      .strictObject({
        /** When set, transfers to any other address are not automatically allowed. */
        allow: z.array(AddressSchema).optional(),
        notAllowlisted: ModeSchema.default('requireApproval'),
      })
      .prefault({}),
    denylist: z.array(AddressSchema).default([]),
    /** Tokens/collections that are not configured in `tokens`/`nfts`. */
    unlistedAssets: ModeSchema.default('requireApproval'),
    /** Calls to contracts that are not allowlisted protocols, or unrecognised functions. */
    unknownContractCalls: ModeSchema.default('requireApproval'),
    contractDeployment: ModeSchema.default('block'),
    session: z
      .strictObject({
        maxDurationSeconds: z.number().int().positive().optional(),
        maxTransactions: z.number().int().positive().optional(),
      })
      .prefault({}),
    limits: z
      .strictObject({
        maxCalls: z.number().int().min(1).max(256).default(16),
        maxNestingDepth: z.number().int().min(0).max(4).default(2),
        maxCalldataBytes: z.number().int().min(4).max(1_048_576).default(131_072),
      })
      .prefault({}),
    /** How long a `requiresApproval` verdict can be approved. */
    approvalTtlSeconds: z.number().int().min(1).max(86_400).default(900),
    simulation: z
      .strictObject({
        /** Applied when a configured simulator cannot simulate the request. */
        onUnavailable: ModeSchema.default('requireApproval'),
      })
      .prefault({}),
  })
  .superRefine((p, ctx) => {
    const owners = new Map<string, string>();
    const claim = (address: string, label: string) => {
      const prior = owners.get(address);
      if (prior) {
        ctx.addIssue({ code: 'custom', message: `${address} is configured as both ${prior} and ${label}` });
      } else {
        owners.set(address, label);
      }
    };
    p.tokens.forEach((t) => claim(t.address, `token ${t.symbol}`));
    p.nfts.forEach((n) => claim(n.address, `collection ${n.name}`));
    // A token/collection may not be a protocol: unrestricted selectors would bypass its asset limits.
    p.protocols.forEach((pr) => claim(pr.address, `protocol ${pr.name}`));

    const deny = new Set(p.denylist);
    const trusted = [
      ...p.approvals.spenders,
      ...(p.recipients.allow ?? []),
      ...p.protocols.map((pr) => pr.address),
      ...p.tokens.map((t) => t.address),
      ...p.nfts.map((n) => n.address),
    ];
    for (const a of trusted) {
      if (deny.has(a)) ctx.addIssue({ code: 'custom', message: `${a} is both denylisted and allowlisted` });
    }
  });

export type PolicyInput = z.input<typeof PolicySchema>;
export type Policy = z.output<typeof PolicySchema>;
export type TokenRule = z.output<typeof TokenRuleSchema>;
export type NftRule = z.output<typeof NftRuleSchema>;
export type ProtocolRule = z.output<typeof ProtocolRuleSchema>;
