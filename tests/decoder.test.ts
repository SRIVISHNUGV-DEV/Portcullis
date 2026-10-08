import { describe, expect, it } from 'vitest';
import { decodeRequest, PERMIT2_ADDRESS } from '../src/decoder.js';
import { compilePolicy } from '../src/policy.js';
import { TransactionRequestSchema } from '../src/schemas.js';
import {
  ALICE, BOB, NFT, ROUTER, TREASURY, UINT256_MAX, UNKNOWN_CONTRACT, UNKNOWN_TOKEN, USDC, WALLET,
  basePolicy, batch, erc1155, erc20, erc721, eth, permit2Approve, tx, usdc, walletExecute, walletExecuteBatch,
} from './helpers.js';

const policy = compilePolicy(basePolicy());
const decode = (input: unknown, p = policy) => decodeRequest(TransactionRequestSchema.parse(input), p);

describe('calldata decoder', () => {
  it('decodes native transfers', () => {
    const r = decode(tx({ to: ALICE, value: eth('0.01') }));
    expect(r.actions).toEqual([{ type: 'native_transfer', path: '0', to: ALICE, amount: eth('0.01') }]);
    expect(r.calls[0]!.value).toBe(eth('0.01'));
  });

  it('decodes ERC-20 transfer, transferFrom, approve, increase/decreaseAllowance', () => {
    const r = decode(batch([
      { to: USDC, data: erc20.transfer(ALICE, usdc('10')) },
      { to: USDC, data: erc20.transferFrom(TREASURY, BOB, usdc('5')) },
      { to: USDC, data: erc20.approve(ROUTER, usdc('7')) },
      { to: USDC, data: erc20.increaseAllowance(ROUTER, usdc('1')) },
      { to: USDC, data: erc20.decreaseAllowance(ROUTER, usdc('1')) },
    ]));
    expect(r.issues).toEqual([]);
    expect(r.actions.map((a) => a.type)).toEqual([
      'token_transfer', 'token_transfer', 'token_approval', 'token_approval', 'token_allowance_decrease',
    ]);
    expect(r.actions[1]).toMatchObject({ from: TREASURY, to: BOB, amount: usdc('5'), method: 'transferFrom' });
    expect(r.actions[2]).toMatchObject({ spender: ROUTER, amount: usdc('7'), unlimited: false, owner: WALLET });
  });

  it('flags unlimited approvals, including Permit2 uint160 max', () => {
    const r = decode(batch([
      { to: USDC, data: erc20.approve(ROUTER, UINT256_MAX) },
      { to: PERMIT2_ADDRESS, data: permit2Approve(USDC, ROUTER, (1n << 160n) - 1n, 0n) },
      { to: USDC, data: erc20.approve(ROUTER, 1n << 200n) },
    ]));
    expect(r.actions.every((a) => a.type === 'token_approval' && a.unlimited)).toBe(true);
    expect(r.actions[1]).toMatchObject({ token: USDC, method: 'permit2.approve' });
  });

  it('only treats the Permit2 selector as an approval at the canonical Permit2 address', () => {
    const r = decode(tx({ to: UNKNOWN_CONTRACT, data: permit2Approve(USDC, ROUTER, 1n, 0n) }));
    expect(r.actions[0]).toMatchObject({ type: 'contract_call', selector: '0x87517c45' });
  });

  it('decodes value-moving token extensions (ERC-677, EIP-3009, EIP-2612)', () => {
    const r = decode(batch([
      { to: USDC, data: erc20.transferAndCall(ALICE, usdc('3'), '0x1234') },
      { to: USDC, data: erc20.transferWithAuthorization(TREASURY, ALICE, usdc('4')) },
      { to: USDC, data: erc20.permit(WALLET, ROUTER, usdc('5')) },
    ]));
    expect(r.actions[0]).toMatchObject({ type: 'token_transfer', method: 'transferAndCall', amount: usdc('3') });
    expect(r.actions[1]).toMatchObject({ type: 'token_transfer', method: 'transferWithAuthorization', from: TREASURY });
    expect(r.actions[2]).toMatchObject({ type: 'token_approval', method: 'permit', spender: ROUTER });
  });

  it('resolves the shared transferFrom/approve selectors using configured asset standards', () => {
    const r = decode(batch([
      { to: NFT, data: erc20.transferFrom(WALLET, ALICE, 7n) },
      { to: NFT, data: erc20.approve(ALICE, 7n) },
      { to: UNKNOWN_TOKEN, data: erc20.transferFrom(WALLET, ALICE, 7n) },
    ]));
    expect(r.actions[0]).toMatchObject({ type: 'nft_transfer', standard: 'erc721', tokenId: 7n });
    expect(r.actions[1]).toMatchObject({ type: 'nft_approval', tokenId: 7n });
    expect(r.actions[2]).toMatchObject({ type: 'token_transfer', standardKnown: false });
  });

  it('decodes ERC-721/1155 transfers and operator approvals', () => {
    const r = decode(batch([
      { to: NFT, data: erc721.safeTransferFrom(WALLET, ALICE, 1n) },
      { to: NFT, data: erc721.safeTransferFromWithData(WALLET, ALICE, 2n, '0xbeef') },
      { to: NFT, data: erc721.setApprovalForAll(BOB, true) },
      { to: UNKNOWN_CONTRACT, data: erc1155.safeTransferFrom(WALLET, ALICE, 3n, 10n) },
      { to: UNKNOWN_CONTRACT, data: erc1155.safeBatchTransferFrom(WALLET, ALICE, [4n, 5n], [1n, 2n]) },
    ]));
    expect(r.issues).toEqual([]);
    expect(r.actions.map((a) => a.type)).toEqual([
      'nft_transfer', 'nft_transfer', 'operator_approval', 'nft_transfer', 'nft_transfer', 'nft_transfer',
    ]);
    expect(r.actions[3]).toMatchObject({ standard: 'erc1155', tokenId: 3n, amount: 10n });
    expect(r.actions[5]).toMatchObject({ tokenId: 5n, amount: 2n });
  });

  it('reports mismatched ERC-1155 batch arrays as malformed', () => {
    const r = decode(tx({ to: UNKNOWN_CONTRACT, data: erc1155.safeBatchTransferFrom(WALLET, ALICE, [1n, 2n], [1n]) }));
    expect(r.issues[0]!.code).toBe('CALLDATA_MALFORMED');
  });

  it('never downgrades a malformed known selector to an unknown call (fail-closed regression)', () => {
    const truncated = erc20.transfer(ALICE, usdc('10')).slice(0, 74);
    const dirty = erc20.transfer(ALICE, usdc('10')).replace(`000000000000000000000000${ALICE.slice(2)}`, `ffffffffffffffffffffffff${ALICE.slice(2)}`);
    const trailing = `${erc20.transfer(ALICE, usdc('10'))}00000000`;
    for (const [data, code] of [[truncated, 'CALLDATA_MALFORMED'], [dirty, 'CALLDATA_NON_CANONICAL'], [trailing, 'CALLDATA_NON_CANONICAL']] as const) {
      const r = decode(tx({ to: USDC, data }));
      expect(r.actions).toEqual([]);
      expect(r.issues[0]!.code).toBe(code);
    }
  });

  it('unwraps smart-wallet execute and executeBatch self-calls', () => {
    const inner = walletExecuteBatch([
      [USDC, 0n, erc20.transfer(ALICE, usdc('1'))],
      [BOB, eth('0.01'), '0x'],
    ]);
    const r = decode(tx({ to: WALLET, data: walletExecute(WALLET, 0n, inner) }));
    expect(r.issues).toEqual([]);
    expect(r.actions).toMatchObject([
      { type: 'token_transfer', path: '0.0.0', amount: usdc('1') },
      { type: 'native_transfer', path: '0.0.1', to: BOB },
    ]);
    expect(r.calls.map((c) => c.path)).toEqual(['0.0.0', '0.0.1']);
  });

  it('enforces the wallet nesting limit', () => {
    let data = erc20.transfer(ALICE, 1n);
    let to = USDC;
    for (let i = 0; i < 3; i++) {
      data = walletExecute(to, 0n, data);
      to = WALLET;
    }
    const r = decode(tx({ to: WALLET, data }));
    expect(r.issues.map((i) => i.code)).toContain('NESTING_TOO_DEEP');
  });

  it('classifies other self-calls, deployments and empty zero-value calls', () => {
    const r = decode(batch([
      { to: WALLET, data: '0x7065cb48' + ALICE.slice(2).padStart(64, '0') },
      { to: null, data: '0x6080604052' },
      { to: UNKNOWN_CONTRACT },
    ]));
    expect(r.actions.map((a) => a.type)).toEqual(['wallet_self_call', 'contract_deployment', 'contract_call']);
    expect(r.actions[2]).toMatchObject({ selector: null });
  });

  it('enforces call-count and calldata-size limits', () => {
    const p = compilePolicy(basePolicy({ limits: { maxCalls: 2, maxCalldataBytes: 68 } }));
    const many = decode(batch([{ to: ALICE, value: 1n }, { to: ALICE, value: 1n }, { to: ALICE, value: 1n }]), p);
    expect(many.issues.map((i) => i.code)).toEqual(['TOO_MANY_CALLS']);
    const big = decode(tx({ to: USDC, data: erc20.transferAndCall(ALICE, 1n, '0x01') }), p);
    expect(big.issues.map((i) => i.code)).toEqual(['CALLDATA_TOO_LARGE']);
  });
});
