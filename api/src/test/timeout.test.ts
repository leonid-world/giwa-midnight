import { describe, expect, it } from 'vitest';
import { OperationTimeoutError, withTimeout } from '../timeout.js';

describe('withTimeout', () => {
  it('returns a value that arrives before the deadline', async () => {
    await expect(withTimeout(Promise.resolve('public-state'), 100)).resolves.toBe('public-state');
  });

  it('rejects a stalled Indexer operation after the deadline', async () => {
    const stalled = new Promise<never>(() => undefined);
    await expect(withTimeout(stalled, 5)).rejects.toBeInstanceOf(OperationTimeoutError);
  });
});
