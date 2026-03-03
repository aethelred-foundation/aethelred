/**
 * Utility functions for Aethelred SDK.
 */

const AETH_DECIMALS = 18;
const UAETH_MULTIPLIER = BigInt(10 ** AETH_DECIMALS);

export function toUaeth(aeth: number | string): bigint {
  const value = typeof aeth === 'string' ? parseFloat(aeth) : aeth;
  return BigInt(Math.floor(value * Number(UAETH_MULTIPLIER)));
}

export function fromUaeth(uaeth: bigint | string): number {
  const value = typeof uaeth === 'string' ? BigInt(uaeth) : uaeth;
  return Number(value) / Number(UAETH_MULTIPLIER);
}

export function formatAeth(uaeth: bigint | string, decimals = 6): string {
  const value = fromUaeth(uaeth);
  return value.toFixed(decimals) + ' AETH';
}

export function isValidAddress(address: string): boolean {
  return /^aeth1[a-z0-9]{38,58}$/.test(address);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function retry<T>(
  fn: () => Promise<T>,
  options: { maxRetries?: number; delay?: number; backoff?: number } = {}
): Promise<T> {
  const { maxRetries = 3, delay = 1000, backoff = 2 } = options;
  
  return new Promise((resolve, reject) => {
    let attempts = 0;
    
    const attempt = async () => {
      try {
        resolve(await fn());
      } catch (error) {
        attempts++;
        if (attempts >= maxRetries) {
          reject(error);
        } else {
          setTimeout(attempt, delay * Math.pow(backoff, attempts - 1));
        }
      }
    };
    
    attempt();
  });
}
