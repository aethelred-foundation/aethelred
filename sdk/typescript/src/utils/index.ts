/**
 * Utility functions for Aethelred SDK.
 */

const AETHEL_DECIMALS = 18;
const UAETHEL_MULTIPLIER = BigInt(10 ** AETHEL_DECIMALS);

export function toUaethel(aethel: number | string): bigint {
  const value = typeof aethel === 'string' ? parseFloat(aethel) : aethel;
  return BigInt(Math.floor(value * Number(UAETHEL_MULTIPLIER)));
}

export function fromUaethel(uaethel: bigint | string): number {
  const value = typeof uaethel === 'string' ? BigInt(uaethel) : uaethel;
  return Number(value) / Number(UAETHEL_MULTIPLIER);
}

export function formatAethel(uaethel: bigint | string, decimals = 6): string {
  const value = fromUaethel(uaethel);
  return value.toFixed(decimals) + ' AETHEL';
}

export function isValidAddress(address: string): boolean {
  return /^aethel1[a-z0-9]{38,58}$/.test(address);
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
