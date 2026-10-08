import { digest } from './canonical.js';
import {
  PolicySchema,
  type NftRule,
  type Policy,
  type PolicyInput,
  type ProtocolRule,
  type TokenRule,
} from './schemas.js';

export class PolicyValidationError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`Invalid firewall policy:\n- ${issues.join('\n- ')}`);
    this.name = 'PolicyValidationError';
  }
}

/** Validated policy with lookup indexes. Immutable once compiled. */
export interface CompiledPolicy {
  readonly policy: Policy;
  /** SHA-256 of the canonical validated policy; recorded in every verdict and audit record. */
  readonly hash: string;
  readonly chainIds: ReadonlySet<number>;
  readonly tokens: ReadonlyMap<string, TokenRule>;
  readonly nfts: ReadonlyMap<string, NftRule>;
  readonly protocols: ReadonlyMap<string, ProtocolRule>;
  readonly trustedSpenders: ReadonlySet<string>;
  readonly denylist: ReadonlySet<string>;
  readonly recipientAllowlist: ReadonlySet<string> | null;
}

export function definePolicy(policy: PolicyInput): PolicyInput {
  return policy;
}

export function compilePolicy(input: PolicyInput | unknown): CompiledPolicy {
  const parsed = PolicySchema.safeParse(input);
  if (!parsed.success) {
    throw new PolicyValidationError(
      parsed.error.issues.map((i) => `${i.path.length ? `${i.path.join('.')}: ` : ''}${i.message}`),
    );
  }
  const policy = parsed.data;
  const protocols = new Map(policy.protocols.map((p) => [p.address, p]));
  return Object.freeze({
    policy,
    hash: digest(policy),
    chainIds: new Set(policy.chainIds),
    tokens: new Map(policy.tokens.map((t) => [t.address, t])),
    nfts: new Map(policy.nfts.map((n) => [n.address, n])),
    protocols,
    trustedSpenders: new Set([...policy.approvals.spenders, ...protocols.keys()]),
    denylist: new Set(policy.denylist),
    recipientAllowlist: policy.recipients.allow ? new Set(policy.recipients.allow) : null,
  });
}
