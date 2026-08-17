import { describe, expect, it, vi } from 'vitest';
import {
  createSingleInFlightOperation,
  OperationInProgressError,
  OperationTimeoutError,
  withTimeout,
} from '../timeout.js';

describe('withTimeout', () => {
  it('returns a value that arrives before the deadline', async () => {
    await expect(withTimeout(Promise.resolve('public-state'), 100)).resolves.toBe('public-state');
  });

  it('rejects a stalled Indexer operation after the deadline', async () => {
    const stalled = new Promise<never>(() => undefined);
    await expect(withTimeout(stalled, 5)).rejects.toBeInstanceOf(OperationTimeoutError);
  });

  it('does not accumulate new operations while a timed-out upstream call is still alive', async () => {
    let settleFirst!: (value: string) => void;
    const firstUpstream = new Promise<string>((resolve) => {
      settleFirst = resolve;
    });
    const operation = vi
      .fn<(argument: string) => Promise<string>>()
      .mockReturnValueOnce(firstUpstream)
      .mockResolvedValueOnce('third-result');
    const run = createSingleInFlightOperation(operation, 5);

    await expect(run('first')).rejects.toBeInstanceOf(OperationTimeoutError);
    await expect(run('second')).rejects.toBeInstanceOf(OperationInProgressError);
    expect(operation).toHaveBeenCalledTimes(1);

    settleFirst('late-result');
    await firstUpstream;
    await Promise.resolve();

    await expect(run('third')).resolves.toBe('third-result');
    expect(operation).toHaveBeenCalledTimes(2);
  });
});
