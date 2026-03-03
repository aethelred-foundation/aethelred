import { describe, expect, it } from 'vitest';

import { isTerminalJobStatus } from './utils';
import { JobStatus } from '../core/types';

describe('react hooks helpers', () => {
  it('detects terminal job states', () => {
    expect(isTerminalJobStatus(JobStatus.COMPLETED)).toBe(true);
    expect(isTerminalJobStatus(JobStatus.FAILED)).toBe(true);
    expect(isTerminalJobStatus(JobStatus.CANCELLED)).toBe(true);
    expect(isTerminalJobStatus(JobStatus.PENDING)).toBe(false);
    expect(isTerminalJobStatus(undefined)).toBe(false);
  });
});
