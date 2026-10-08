import { describe, expect, it } from "vitest";
import { actionBar, applyReview } from "./action-bar";
import type { Status, Game } from "./types";

function status(
  selections: string[] = [],
  appliedCount: number | null = null,
  dirty = false,
): Status {
  return {
    snapshot: { preferences: { blockedRegions: selections } },
    appliedCount,
    dirty,
  } as unknown as Status;
}

describe("compact action bar", () => {
  it("stays hidden during startup and when there is no pending work", () => {
    expect(actionBar(null, true).visible).toBe(false);
    expect(actionBar(status(), false).visible).toBe(false);
    expect(actionBar(status([], 0, false), false).visible).toBe(false);
  });
  it("does not offer Apply for unreadable saved selections on startup", () => {
    expect(actionBar(status(["cs2:eu"]), false)).toEqual({
      visible: false,
      apply: false,
      key: "active_rules_count",
      values: { count: 0 },
    });
  });
  it("stays available when deselecting the last active rule so it can be removed", () => {
    expect(actionBar(status([], 4, true), false)).toEqual({
      visible: true,
      apply: true,
      key: "pending_changes_count",
      values: { count: 0 },
    });
  });
  it("shows one applied summary and a working status during operations", () => {
    const applied = status(["cs2:eu"], 4, false);
    expect(actionBar(applied, false)).toEqual({
      visible: true,
      apply: false,
      key: "active_rules_count",
      values: { count: 4 },
    });
    expect(actionBar(applied, true).key).toBe("Working…");
  });
  it("counts only explicit selections, without duplicates", () => {
    const pending = status(["cs2:eu", "cs2:eu"], null, true);
    expect(actionBar(pending, false).values.count).toBe(1);
    pending.snapshot.preferences.blockedRegions = [];
    expect(actionBar(pending, false).apply).toBe(true);
  });
  it("recovery hints alone never offer Apply or claim blocks are active", () => {
    const recovered = status();
    recovered.snapshot.preferences.lastAppliedGameIds = ["cs2"];
    expect(actionBar(recovered, false).visible).toBe(false);
    expect(actionBar(recovered, false).apply).toBe(false);
    expect(actionBar(recovered, false).values.count).toBe(0);
  });
  it("offers Apply only for known differences or genuine edits, including unreadable removals", () => {
    expect(actionBar(status(["cs2:eu"], 0, true), false).apply).toBe(true);
    expect(actionBar(status(["cs2:eu"], null, true), false).apply).toBe(true);
    expect(actionBar(status([], null, true), false).apply).toBe(true);
    expect(actionBar(status(["cs2:eu"], null, false), false).apply).toBe(false);
    expect(actionBar(status(["cs2:eu"], 4, false), false).apply).toBe(false);
  });
  it("reviews actual selected games and nonempty regions once", () => {
    const pending = status([
      "cs2:eu",
      "cs2:eu",
      "cs2:empty",
      "unknown:eu",
      "deadlock:asia",
    ]);
    pending.snapshot.games = [
      {
        id: "cs2",
        name: "Counter-Strike 2",
        regions: [
          { id: "eu", endpoints: [{}] },
          { id: "empty", endpoints: [] },
        ],
      },
      {
        id: "deadlock",
        name: "Deadlock",
        regions: [{ id: "asia", endpoints: [{}] }],
      },
    ] as Game[];
    expect(applyReview(pending)).toEqual({
      games: ["Counter-Strike 2", "Deadlock"],
      regions: 2,
    });
    expect(applyReview(null)).toEqual({ games: [], regions: 0 });
    pending.snapshot.preferences.blockedRegions = [];
    expect(applyReview(pending)).toEqual({ games: [], regions: 0 });
  });
});
