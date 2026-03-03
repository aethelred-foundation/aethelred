declare interface GPUAdapterInfo {
  vendor?: string;
  architecture?: string;
  device?: string;
  description?: string;
}

declare interface GPUBuffer {
  destroy(): void;
  mapAsync(mode: number): Promise<void>;
  getMappedRange(): ArrayBuffer;
  unmap(): void;
}

declare interface GPUDevice {
  queue?: {
    submit?(commands: unknown[]): void;
    writeBuffer?(
      buffer: GPUBuffer,
      bufferOffset: number,
      data: BufferSource,
      dataOffset?: number,
      size?: number
    ): void;
  };
  createBuffer(descriptor: {
    size: number;
    usage: number;
    mappedAtCreation?: boolean;
  }): GPUBuffer;
}

declare interface GPUAdapter {
  info?: GPUAdapterInfo;
  features?: {
    has(feature: string): boolean;
  };
  limits?: {
    maxBufferSize?: number;
    maxStorageBufferBindingSize?: number;
    maxComputeWorkgroupsPerDimension?: number;
    maxComputeWorkgroupSizeX?: number;
    maxComputeWorkgroupSizeY?: number;
    maxComputeWorkgroupSizeZ?: number;
    maxComputeInvocationsPerWorkgroup?: number;
  };
  requestAdapterInfo?(): Promise<GPUAdapterInfo>;
  requestDevice(): Promise<GPUDevice>;
}

declare const GPUBuffer: {
  prototype: GPUBuffer;
};

declare const GPUBufferUsage: {
  STORAGE: number;
  COPY_SRC: number;
  COPY_DST: number;
  MAP_READ: number;
};

declare const GPUMapMode: {
  READ: number;
};
