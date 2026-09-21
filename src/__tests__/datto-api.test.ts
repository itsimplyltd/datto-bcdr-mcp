/**
 * Pure-logic coverage for src/datto-api.ts's response-shape normalization
 * and input validation — the parts that don't need a network call.
 */
import { describe, it, expect } from "vitest";
import {
  normalizeIndexKeyedAssets,
  unwrapAssetArray,
  isValidSinceDays,
  DattoBcdrNotFoundError,
  SINCE_DAYS_MIN,
  SINCE_DAYS_MAX,
} from "../datto-api.js";

describe("normalizeIndexKeyedAssets", () => {
  it(
    "REGRESSION: an index-keyed {'0':{...},'1':{...}} payload yields 2 assets, never 0 — " +
      "this is the exact bug datto_bcdr_list_assets shipped with. The upstream " +
      "PaginatedIterable did `response.items ?? []` against this shape, which is " +
      "always undefined here, so the tool silently reported zero assets for a " +
      "device that had two.",
    () => {
      const response = {
        "0": { volume: "aaa", name: "web01" },
        "1": { volume: "bbb", name: "web02" },
      };
      const assets = normalizeIndexKeyedAssets(response);
      expect(assets).toHaveLength(2);
      expect(assets.map((a) => a.volume)).toEqual(["aaa", "bbb"]);
    }
  );

  it("returns an empty array for an empty index-keyed object (a device with no assets)", () => {
    expect(normalizeIndexKeyedAssets({})).toEqual([]);
  });

  it("returns an empty array for null/undefined/non-object input rather than throwing", () => {
    expect(normalizeIndexKeyedAssets(null)).toEqual([]);
    expect(normalizeIndexKeyedAssets(undefined)).toEqual([]);
    expect(normalizeIndexKeyedAssets("not an object")).toEqual([]);
  });
});

describe("unwrapAssetArray", () => {
  it("unwraps the single matching element from the /asset/{volume} array response", () => {
    const asset = unwrapAssetArray([{ volume: "ccc", name: "sql01" }], "ccc");
    expect(asset).toEqual({ volume: "ccc", name: "sql01" });
  });

  it("throws DattoBcdrNotFoundError on the empty-array not-found case", () => {
    expect(() => unwrapAssetArray([], "missing-volume")).toThrow(DattoBcdrNotFoundError);
    expect(() => unwrapAssetArray([], "missing-volume")).toThrow(/missing-volume/);
  });

  it("treats a non-array response as not-found rather than crashing", () => {
    expect(() => unwrapAssetArray({ not: "an array" }, "vol")).toThrow(DattoBcdrNotFoundError);
    expect(() => unwrapAssetArray(null, "vol")).toThrow(DattoBcdrNotFoundError);
  });
});

describe("isValidSinceDays", () => {
  it(`rejects 0 (below the ${SINCE_DAYS_MIN}-day floor)`, () => {
    expect(isValidSinceDays(0)).toBe(false);
  });

  it(`rejects ${SINCE_DAYS_MAX + 1} (above the ${SINCE_DAYS_MAX}-day ceiling)`, () => {
    expect(isValidSinceDays(31)).toBe(false);
  });

  it("rejects non-integers", () => {
    expect(isValidSinceDays(1.5)).toBe(false);
    expect(isValidSinceDays(7.1)).toBe(false);
  });

  it("rejects non-numbers (e.g. a numeric string)", () => {
    expect(isValidSinceDays("7")).toBe(false);
    expect(isValidSinceDays(undefined)).toBe(false);
    expect(isValidSinceDays(null)).toBe(false);
  });

  it(`accepts the boundary values ${SINCE_DAYS_MIN} and ${SINCE_DAYS_MAX}`, () => {
    expect(isValidSinceDays(SINCE_DAYS_MIN)).toBe(true);
    expect(isValidSinceDays(SINCE_DAYS_MAX)).toBe(true);
  });

  it("accepts a typical mid-range value", () => {
    expect(isValidSinceDays(7)).toBe(true);
  });
});
