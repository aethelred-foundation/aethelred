import { JobStatus } from "../core/types";

export function isTerminalJobStatus(status: JobStatus | undefined): boolean {
  return Boolean(status && [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED].includes(status));
}
