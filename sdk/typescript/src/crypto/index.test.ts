import { describe, expect, it } from "vitest";

import { fromHex, sha256Hex, toHex } from "./index";

describe("crypto", () => {
  it("computes deterministic sha256 hex digests", () => {
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  it("round-trips bytes through hex encoding", () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255]);
    const hex = toHex(bytes);

    expect(hex).toBe("000102feff");
    expect(Array.from(fromHex(hex))).toEqual(Array.from(bytes));
  });

  it("hashes UTF-8 strings and Uint8Array inputs consistently", () => {
    const text = "AETHELRED";
    const bytes = new TextEncoder().encode(text);

    expect(sha256Hex(text)).toBe(sha256Hex(bytes));
  });

  it("returns 32-byte SHA256 output", () => {
    const digest = fromHex(sha256Hex("length-check"));
    expect(digest).toHaveLength(32);
  });

  it("supports empty byte arrays in hex round-trip", () => {
    const empty = new Uint8Array([]);
    const hex = toHex(empty);

    expect(hex).toBe("");
    expect(Array.from(fromHex(hex))).toEqual([]);
  });

  it("throws for invalid hex input", () => {
    expect(() => fromHex("zz")).toThrow();
  });
});
