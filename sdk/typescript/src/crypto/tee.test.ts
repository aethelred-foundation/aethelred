import { describe, expect, it } from "vitest";

import {
  parseNitroDocument,
  type NitroDocument,
  TEEVerifier,
  type TEEAttestation,
} from "./tee";

function makeAttestation(overrides: Partial<TEEAttestation>): TEEAttestation {
  return {
    platform: "NITRO",
    quote: new Uint8Array([1, 2, 3]),
    timestamp: new Date(),
    reportData: new Uint8Array([9, 9, 9]),
    measurement: new Uint8Array(48),
    ...overrides,
  };
}

describe("tee attestation verification (fail-closed)", () => {
  it("parseNitroDocument throws without an injected CBOR/COSE parser", () => {
    expect(() => parseNitroDocument(new Uint8Array([0xa1, 0x01]))).toThrow(/nitro attestation parsing requires/i);
  });

  it("SEV verification fails closed when no backend verifier is configured", async () => {
    const verifier = new TEEVerifier();
    const attestation: TEEAttestation = {
      platform: "SEV",
      quote: new Uint8Array(1184),
      timestamp: new Date(),
      reportData: new Uint8Array(),
      measurement: new Uint8Array(48),
    };

    const result = await verifier.verify(attestation);

    expect(result.valid).toBe(false);
    expect(result.signatureValid).toBe(false);
    expect(result.errors.some((e) => e.includes("SEV report signature verification failed"))).toBe(true);
  });

  it("Nitro verification fails closed when no parser/verifier is configured", async () => {
    const verifier = new TEEVerifier();
    const result = await verifier.verify(makeAttestation({ platform: "NITRO" }));

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Nitro parse error"))).toBe(true);
  });

  it("Nitro verification rejects placeholder root certificates", async () => {
    const pcr0 = new Uint8Array(48).fill(0x11);
    const measurementHex = Array.from(pcr0)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const fakeDoc: NitroDocument = {
      moduleId: "m1",
      timestamp: Date.now(),
      digest: "SHA384",
      pcrs: new Map([[0, pcr0]]),
      certificate: new Uint8Array([1]),
      cabundle: [],
      userData: null,
      nonce: new Uint8Array([1]),
      publicKey: null,
    };

    const verifier = new TEEVerifier({
      nitroDocumentParser: () => fakeDoc,
      nitroCertificateVerifier: async () => true,
      nitroTrustedRootsPem: ["-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"],
      expectedMeasurements: [{ platform: "NITRO", measurement: measurementHex }],
    });

    const result = await verifier.verify(makeAttestation({ platform: "NITRO" }));

    expect(result.valid).toBe(false);
    expect(result.signatureValid).toBe(false);
    expect(result.errors.some((e) => e.includes("Nitro certificate chain verification failed"))).toBe(true);
  });

  it("Nitro verification fails closed when trusted roots are omitted even with parser/verifier", async () => {
    const pcr0 = new Uint8Array(48).fill(0x33);
    const measurementHex = Array.from(pcr0)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const fakeDoc: NitroDocument = {
      moduleId: "m3",
      timestamp: Date.now(),
      digest: "SHA384",
      pcrs: new Map([[0, pcr0]]),
      certificate: new Uint8Array([1, 2, 3]),
      cabundle: [],
      userData: null,
      nonce: new Uint8Array([7]),
      publicKey: null,
    };

    const verifier = new TEEVerifier({
      nitroDocumentParser: async () => fakeDoc,
      nitroCertificateVerifier: async () => true,
      nitroTrustedRootsPem: [],
      expectedMeasurements: [{ platform: "NITRO", measurement: measurementHex }],
    });

    const result = await verifier.verify(makeAttestation({ platform: "NITRO" }));

    expect(result.valid).toBe(false);
    expect(result.signatureValid).toBe(false);
    expect(result.errors.some((e) => e.includes("Nitro certificate chain verification failed"))).toBe(true);
  });

  it("Nitro verification succeeds when parser, verifier, and trusted roots are provided", async () => {
    const pcr0 = new Uint8Array(48).fill(0x22);
    const measurementHex = Array.from(pcr0)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const fakeDoc: NitroDocument = {
      moduleId: "m2",
      timestamp: Date.now(),
      digest: "SHA384",
      pcrs: new Map([[0, pcr0]]),
      certificate: new Uint8Array([1, 2, 3]),
      cabundle: [],
      userData: null,
      nonce: new Uint8Array([9]),
      publicKey: null,
    };

    const verifier = new TEEVerifier({
      nitroDocumentParser: async () => fakeDoc,
      nitroCertificateVerifier: async (doc, roots) => doc.certificate.length > 0 && roots.length === 1,
      nitroTrustedRootsPem: ["-----BEGIN CERTIFICATE-----\nMIIBFAKE\n-----END CERTIFICATE-----"],
      expectedMeasurements: [{ platform: "NITRO", measurement: measurementHex }],
    });

    const result = await verifier.verify(makeAttestation({ platform: "NITRO" }));

    expect(result.valid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.measurement).toBe(measurementHex);
    expect(result.errors).toHaveLength(0);
  });
});
