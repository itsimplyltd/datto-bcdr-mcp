/**
 * Pure-logic coverage for src/datto-api.ts's response-shape normalization
 * and input validation — the parts that don't need a network call.
 */
import { describe, it, expect } from "vitest";
import {
  normalizeIndexKeyedAssets,
  unwrapAssetArray,
  DattoBcdrNotFoundError,
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

