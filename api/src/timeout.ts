export class OperationTimeoutError extends Error {
  constructor() {
    super('The local Midnight Indexer query timed out.');
    this.name = 'OperationTimeoutError';
  }
}

export class OperationInProgressError extends Error {
  constructor() {
    super('A local Midnight Indexer query is already in progress.');
    this.name = 'OperationInProgressError';
  }
}

export function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new OperationTimeoutError()), timeoutMs);

    operation.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

/**
 * Keep at most one upstream operation alive, including after the caller-facing
 * timeout fires. This prevents repeated requests from accumulating orphaned
 * Indexer queries when the SDK does not expose an AbortSignal.
 */
export function createSingleInFlightOperation<TArgument, TResult>(
  operation: (argument: TArgument) => Promise<TResult>,
  timeoutMs: number,
): (argument: TArgument) => Promise<TResult> {
  let inFlight: Promise<TResult> | null = null;

  return async (argument) => {
    if (inFlight !== null) {
      throw new OperationInProgressError();
    }

    const current = operation(argument);
    inFlight = current;
    void current.then(
      () => {
        if (inFlight === current) inFlight = null;
      },
      () => {
        if (inFlight === current) inFlight = null;
      },
    );

    return withTimeout(current, timeoutMs);
  };
}
