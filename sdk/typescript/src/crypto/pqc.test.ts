import { afterEach, describe, expect, it } from "vitest";

import {
  ALGORITHM_PARAMS,
  SECURITY_LEVEL_MAP,
  checkPQCAvailability,
  configurePQCProvider,
  getPQCProvider,
  getRecommendedAlgorithms,
  hasConfiguredPQCProvider,
  HybridCrypto,
  type EncapsulationResult,
  type KEMAlgorithm,
  type KEMKeyPair,
  PQCImplementationUnavailableError,
  type PQCProvider,
  type SignatureAlgorithm,
  type SignatureKeyPair,
} from "./pqc";

class FakePQCProvider implements PQCProvider {
  async kemKeypair(algorithm: KEMAlgorithm): Promise<KEMKeyPair> {
    const params = ALGORITHM_PARAMS[algorithm] as { publicKeySize: number; secretKeySize: number };
    return {
      algorithm,
      publicKey: new Uint8Array(params.publicKeySize).fill(1),
      secretKey: new Uint8Array(params.secretKeySize).fill(2),
    };
  }

  async encapsulate(_publicKey: Uint8Array, algorithm: KEMAlgorithm): Promise<EncapsulationResult> {
    const params = ALGORITHM_PARAMS[algorithm] as { ciphertextSize: number; sharedSecretSize: number };
    return {
      ciphertext: new Uint8Array(params.ciphertextSize).fill(3),
      sharedSecret: new Uint8Array(params.sharedSecretSize).fill(4),
    };
  }

  async decapsulate(_secretKey: Uint8Array, _ciphertext: Uint8Array, _algorithm: KEMAlgorithm): Promise<Uint8Array> {
    return new Uint8Array(32).fill(5);
  }

  async signKeypair(algorithm: SignatureAlgorithm): Promise<SignatureKeyPair> {
    const params = ALGORITHM_PARAMS[algorithm] as { publicKeySize: number; secretKeySize: number };
    return {
      algorithm,
      publicKey: new Uint8Array(params.publicKeySize).fill(6),
      secretKey: new Uint8Array(params.secretKeySize).fill(7),
    };
  }

  async sign(message: Uint8Array, _secretKey: Uint8Array, algorithm: SignatureAlgorithm): Promise<Uint8Array> {
    const params = ALGORITHM_PARAMS[algorithm] as { signatureSize: number };
    const out = new Uint8Array(params.signatureSize);
    out.set(message.slice(0, Math.min(message.length, out.length)));
    return out;
  }

  async verify(message: Uint8Array, signature: Uint8Array, _publicKey: Uint8Array, algorithm: SignatureAlgorithm): Promise<boolean> {
    const params = ALGORITHM_PARAMS[algorithm] as { signatureSize: number };
    if (signature.length !== params.signatureSize) return false;
    const expected = new Uint8Array(params.signatureSize);
    expected.set(message.slice(0, Math.min(message.length, expected.length)));
    return signature.every((b, i) => b === expected[i]);
  }
}

describe("pqc (secure provider injection)", () => {
  afterEach(() => {
    configurePQCProvider(null);
  });

  it("fails closed when no PQC backend is configured for sign()", async () => {
    const provider = getPQCProvider();

    await expect(
      provider.sign(new Uint8Array([1, 2, 3]), new Uint8Array(32), "Dilithium3")
    ).rejects.toBeInstanceOf(PQCImplementationUnavailableError);
  });

  it("fails closed when no PQC backend is configured for verify()", async () => {
    const provider = getPQCProvider();
    const sigLen = (ALGORITHM_PARAMS["Dilithium3"] as { signatureSize: number }).signatureSize;

    await expect(
      provider.verify(new Uint8Array([1]), new Uint8Array(sigLen), new Uint8Array(32), "Dilithium3")
    ).rejects.toBeInstanceOf(PQCImplementationUnavailableError);
  });

  it("fails closed when no PQC backend is configured for kemKeypair()", async () => {
    const provider = getPQCProvider();
    await expect(
      provider.kemKeypair("ML-KEM-768")
    ).rejects.toBeInstanceOf(PQCImplementationUnavailableError);
  });

  it("fails closed when no PQC backend is configured for encapsulate()", async () => {
    const provider = getPQCProvider();
    await expect(
      provider.encapsulate(new Uint8Array(32), "ML-KEM-768")
    ).rejects.toBeInstanceOf(PQCImplementationUnavailableError);
  });

  it("fails closed when no PQC backend is configured for decapsulate()", async () => {
    const provider = getPQCProvider();
    await expect(
      provider.decapsulate(new Uint8Array(32), new Uint8Array(32), "ML-KEM-768")
    ).rejects.toBeInstanceOf(PQCImplementationUnavailableError);
  });

  it("fails closed when no PQC backend is configured for signKeypair()", async () => {
    const provider = getPQCProvider();
    await expect(
      provider.signKeypair("ML-DSA-65")
    ).rejects.toBeInstanceOf(PQCImplementationUnavailableError);
  });

  it("delegates sign/verify to injected backend and rejects forged signatures", async () => {
    configurePQCProvider(new FakePQCProvider());
    const provider = getPQCProvider();
    const message = new Uint8Array([9, 8, 7, 6]);
    const sig = await provider.sign(message, new Uint8Array(64), "Dilithium3");

    await expect(provider.verify(message, sig, new Uint8Array(64), "Dilithium3")).resolves.toBe(true);

    const forged = sig.slice();
    forged[0] ^= 0xff;
    await expect(provider.verify(message, forged, new Uint8Array(64), "Dilithium3")).resolves.toBe(false);
  });

  it("delegates kemKeypair to injected backend", async () => {
    configurePQCProvider(new FakePQCProvider());
    const provider = getPQCProvider();
    const keypair = await provider.kemKeypair("ML-KEM-768");
    expect(keypair.algorithm).toBe("ML-KEM-768");
    expect(keypair.publicKey.length).toBe(ALGORITHM_PARAMS["ML-KEM-768"].publicKeySize);
    expect(keypair.secretKey.length).toBe(ALGORITHM_PARAMS["ML-KEM-768"].secretKeySize);
  });

  it("delegates encapsulate to injected backend", async () => {
    configurePQCProvider(new FakePQCProvider());
    const provider = getPQCProvider();
    const result = await provider.encapsulate(new Uint8Array(32), "ML-KEM-768");
    expect(result.ciphertext.length).toBe(ALGORITHM_PARAMS["ML-KEM-768"].ciphertextSize);
    expect(result.sharedSecret.length).toBe(ALGORITHM_PARAMS["ML-KEM-768"].sharedSecretSize);
  });

  it("delegates decapsulate to injected backend", async () => {
    configurePQCProvider(new FakePQCProvider());
    const provider = getPQCProvider();
    const result = await provider.decapsulate(new Uint8Array(32), new Uint8Array(32), "ML-KEM-768");
    expect(result.length).toBe(32);
  });

  it("delegates signKeypair to injected backend", async () => {
    configurePQCProvider(new FakePQCProvider());
    const provider = getPQCProvider();
    const keypair = await provider.signKeypair("ML-DSA-65");
    expect(keypair.algorithm).toBe("ML-DSA-65");
    expect(keypair.publicKey.length).toBe(ALGORITHM_PARAMS["ML-DSA-65"].publicKeySize);
    expect(keypair.secretKey.length).toBe(ALGORITHM_PARAMS["ML-DSA-65"].secretKeySize);
  });

  it("reports availability based on configured backend", async () => {
    await expect(checkPQCAvailability()).resolves.toMatchObject({
      configuredProvider: false,
      wasmSupport: false,
    });

    configurePQCProvider(new FakePQCProvider());
    await expect(checkPQCAvailability()).resolves.toMatchObject({
      configuredProvider: true,
      wasmSupport: true,
    });
  });

  it("hasConfiguredPQCProvider reflects backend state", () => {
    expect(hasConfiguredPQCProvider()).toBe(false);
    configurePQCProvider(new FakePQCProvider());
    expect(hasConfiguredPQCProvider()).toBe(true);
  });

  it("getRecommendedAlgorithms returns correct algorithms for each security level", () => {
    expect(getRecommendedAlgorithms(1)).toEqual(SECURITY_LEVEL_MAP[1]);
    expect(getRecommendedAlgorithms(3)).toEqual(SECURITY_LEVEL_MAP[3]);
    expect(getRecommendedAlgorithms(5)).toEqual(SECURITY_LEVEL_MAP[5]);
  });

  it("PQCImplementationUnavailableError has correct name and message", () => {
    const err = new PQCImplementationUnavailableError("testOp");
    expect(err.name).toBe("PQCImplementationUnavailableError");
    expect(err.message).toContain("testOp");
    expect(err.message).toContain("unavailable");
  });

  it("checkPQCAvailability returns all algorithm lists", async () => {
    const avail = await checkPQCAvailability();
    expect(avail.availableKEMAlgorithms).toContain("ML-KEM-512");
    expect(avail.availableKEMAlgorithms).toContain("ML-KEM-768");
    expect(avail.availableKEMAlgorithms).toContain("ML-KEM-1024");
    expect(avail.availableSignatureAlgorithms).toContain("ML-DSA-44");
    expect(avail.availableSignatureAlgorithms).toContain("ML-DSA-65");
    expect(avail.availableSignatureAlgorithms).toContain("ML-DSA-87");
    expect(avail.nativeSupport).toBe(false);
  });

  it("initialize() is idempotent", async () => {
    const provider = getPQCProvider();
    // Call initialize multiple times - should not throw
    await (provider as any).initialize();
    await (provider as any).initialize();
    // Still works after multiple initializations
    expect(hasConfiguredPQCProvider()).toBe(false);
  });
});

describe("HybridCrypto", () => {
  afterEach(() => {
    configurePQCProvider(null);
  });

  it("generateHybridKEMKeyPair produces classical and PQC keypairs", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const result = await hybrid.generateHybridKEMKeyPair(3);

    expect(result.classical).toBeDefined();
    expect(result.classical.publicKey).toBeDefined();
    expect(result.classical.privateKey).toBeDefined();
    expect(result.pqc.algorithm).toBe("ML-KEM-768");
    expect(result.pqc.publicKey.length).toBe(ALGORITHM_PARAMS["ML-KEM-768"].publicKeySize);
  });

  it("generateHybridKEMKeyPair uses default security level 3", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const result = await hybrid.generateHybridKEMKeyPair();

    expect(result.pqc.algorithm).toBe("ML-KEM-768");
  });

  it("generateHybridKEMKeyPair supports security level 1", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const result = await hybrid.generateHybridKEMKeyPair(1);

    expect(result.pqc.algorithm).toBe("ML-KEM-512");
  });

  it("generateHybridKEMKeyPair supports security level 5", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const result = await hybrid.generateHybridKEMKeyPair(5);

    expect(result.pqc.algorithm).toBe("ML-KEM-1024");
  });

  it("hybridEncapsulate produces combined shared secret", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridKEMKeyPair(3);

    const result = await hybrid.hybridEncapsulate(
      keys.classical.publicKey,
      keys.pqc.publicKey,
      3,
    );

    expect(result.classicalCiphertext).toBeInstanceOf(Uint8Array);
    expect(result.classicalCiphertext.length).toBeGreaterThan(0);
    expect(result.pqcCiphertext).toBeInstanceOf(Uint8Array);
    expect(result.pqcCiphertext.length).toBe(ALGORITHM_PARAMS["ML-KEM-768"].ciphertextSize);
    expect(result.combinedSharedSecret).toBeInstanceOf(Uint8Array);
    expect(result.combinedSharedSecret.length).toBe(32);
  });

  it("hybridEncapsulate uses default security level", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridKEMKeyPair();

    const result = await hybrid.hybridEncapsulate(
      keys.classical.publicKey,
      keys.pqc.publicKey,
    );

    expect(result.combinedSharedSecret.length).toBe(32);
  });

  it("generateHybridSignatureKeyPair produces classical and PQC keypairs", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const result = await hybrid.generateHybridSignatureKeyPair(3);

    expect(result.classical).toBeDefined();
    expect(result.classical.publicKey).toBeDefined();
    expect(result.classical.privateKey).toBeDefined();
    expect(result.pqc.algorithm).toBe("ML-DSA-65");
    expect(result.pqc.publicKey.length).toBe(ALGORITHM_PARAMS["ML-DSA-65"].publicKeySize);
  });

  it("generateHybridSignatureKeyPair uses default security level", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const result = await hybrid.generateHybridSignatureKeyPair();

    expect(result.pqc.algorithm).toBe("ML-DSA-65");
  });

  it("hybridSign produces classical and PQC signatures", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridSignatureKeyPair(3);

    const message = new Uint8Array([1, 2, 3, 4, 5]);
    const result = await hybrid.hybridSign(
      message,
      keys.classical.privateKey,
      keys.pqc.secretKey,
      3,
    );

    expect(result.classicalSignature).toBeInstanceOf(Uint8Array);
    expect(result.classicalSignature.length).toBeGreaterThan(0);
    expect(result.pqcSignature).toBeInstanceOf(Uint8Array);
    expect(result.pqcSignature.length).toBe(ALGORITHM_PARAMS["ML-DSA-65"].signatureSize);
  });

  it("hybridSign uses default security level", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridSignatureKeyPair();

    const message = new Uint8Array([10, 20, 30]);
    const result = await hybrid.hybridSign(
      message,
      keys.classical.privateKey,
      keys.pqc.secretKey,
    );

    expect(result.classicalSignature.length).toBeGreaterThan(0);
  });

  it("hybridVerify validates both classical and PQC signatures", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridSignatureKeyPair(3);

    const message = new Uint8Array([7, 8, 9]);
    const sig = await hybrid.hybridSign(
      message,
      keys.classical.privateKey,
      keys.pqc.secretKey,
      3,
    );

    const result = await hybrid.hybridVerify(
      message,
      sig,
      keys.classical.publicKey,
      keys.pqc.publicKey,
      3,
    );

    expect(result.classicalValid).toBe(true);
    expect(result.pqcValid).toBe(true);
    expect(result.bothValid).toBe(true);
  });

  it("hybridVerify uses default security level", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridSignatureKeyPair();

    const message = new Uint8Array([1]);
    const sig = await hybrid.hybridSign(
      message,
      keys.classical.privateKey,
      keys.pqc.secretKey,
    );

    const result = await hybrid.hybridVerify(
      message,
      sig,
      keys.classical.publicKey,
      keys.pqc.publicKey,
    );

    expect(typeof result.bothValid).toBe("boolean");
  });

  it("hybridVerify detects tampered classical signature", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridSignatureKeyPair(3);

    const message = new Uint8Array([1, 2, 3]);
    const sig = await hybrid.hybridSign(
      message,
      keys.classical.privateKey,
      keys.pqc.secretKey,
      3,
    );

    // Tamper with the classical signature
    const tampered = { ...sig, classicalSignature: new Uint8Array(sig.classicalSignature.length).fill(0) };
    const result = await hybrid.hybridVerify(
      message,
      tampered,
      keys.classical.publicKey,
      keys.pqc.publicKey,
      3,
    );

    expect(result.classicalValid).toBe(false);
    expect(result.bothValid).toBe(false);
  });

  it("hybridVerify detects tampered PQC signature", async () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto(getPQCProvider());
    const keys = await hybrid.generateHybridSignatureKeyPair(3);

    const message = new Uint8Array([5, 6, 7]);
    const sig = await hybrid.hybridSign(
      message,
      keys.classical.privateKey,
      keys.pqc.secretKey,
      3,
    );

    // Tamper with the PQC signature
    const tampered = { ...sig, pqcSignature: new Uint8Array(sig.pqcSignature.length).fill(0xff) };
    const result = await hybrid.hybridVerify(
      message,
      tampered,
      keys.classical.publicKey,
      keys.pqc.publicKey,
      3,
    );

    expect(result.pqcValid).toBe(false);
    expect(result.bothValid).toBe(false);
  });

  it("constructor uses default PQC provider when none specified", () => {
    configurePQCProvider(new FakePQCProvider());
    const hybrid = new HybridCrypto();
    expect(hybrid).toBeDefined();
  });
});
