import { describe, expect, it } from "vitest";
import {
  areaSelection,
  areaBlockDescription,
  blockDescription,
  blockNote,
  selectionDescription,
  regionBlockState,
  toggleKeys,
  libraryGames,
  libraryCandidates,
  gameBlockState,
  blockGameIds,
} from "./game";
import { selectedLocale, translate } from "./i18n";
import type { Game, Preferences, Locale, Scan, Status } from "./types";

describe("game library", () => {
  it("does not describe saved switches as confirmed blocks", () => {
    const app = { appliedCount: null, dirty: true } as Status;
    expect(areaBlockDescription(app, ["one:eu"])).toBe("");
    expect(selectionDescription(true, 2)).toBe("");
    expect(selectionDescription(false, 1)).toBe("Some servers selected");
    expect(selectionDescription(false, 0)).toBe("");
    app.appliedCount = 2;
    app.dirty = false;
    expect(areaBlockDescription(app, ["one:eu"])).toBe("");
    app.regionStates = { "one:eu": "blocked" };
    expect(areaBlockDescription(app, ["one:eu"])).toBe("Blocked");
    app.dirty = true;
    expect(areaBlockDescription(app, ["one:eu"])).toBe("Blocked");
    app.regionStates["one:other"] = "none";
    expect(areaBlockDescription(app, ["one:eu", "one:other"])).toBe("Blocked");
    app.regionStates["one:eu"] = "partial";
    expect(areaBlockDescription(app, ["one:eu"])).toBe("Blocked");
    expect(blockDescription("partial")).toBe("Blocked");
    expect(blockNote(app, ["one:eu"])).toContain("Some targets are blocked");
    app.regionStates["one:eu"] = "none";
    expect(areaBlockDescription(app, ["one:eu"])).toBe("Not blocked");
    expect(areaBlockDescription(app, [])).toBe("No targets configured");
    app.appliedCount = null;
    expect(regionBlockState(app, "one:eu")).toBe("unknown");
    expect(blockDescription("unknown")).toBe("");
    expect(areaBlockDescription(app, ["one:eu"])).toBe("");
    expect(blockNote(app, ["one:eu"])).toBe("");
    app.appliedCount = 0;
    app.regionStates = {};
    expect(areaBlockDescription(app, ["one:new"])).toBe("Not blocked");
  });
  const games = ["cs2", "deadlock", "overwatch2", "custom-mine"].map(
    (id) => ({ id, name: id }) as Game,
  );
  const scan: Scan = {
    games: [
      {
        id: "cs2",
        name: "Counter-Strike 2",
        launcher: "Steam",
        directory: "/games/cs2",
      },
    ],
    warnings: [],
  };
  it("does not present default JSON files as installations", () => {
    expect(libraryGames(games, [])).toEqual([]);
    expect(libraryCandidates(games.slice(0, 3), scan, false, [])).toEqual([]);
  });
  it("keeps detection separate from saved sidebar membership", () => {
    expect(
      libraryGames(games, ["cs2", "custom-mine"]).map((g) => g.id),
    ).toEqual(["cs2", "custom-mine"]);
    expect(libraryCandidates(games, scan, true, []).map((g) => g.id)).toEqual([
      "cs2",
      "custom-mine",
    ]);
  });
  it("keeps explicit imports accessible without pretending they were detected", () => {
    expect(
      libraryGames(games.slice(0, 3), ["deadlock"]).map((g) => g.id),
    ).toEqual(["deadlock"]);
  });
  it("keeps deselected blocking games accessible without labelling saved toggles active", () => {
    const status = {
      snapshot: {
        preferences: { blockedRegions: ["cs2:eu"], lastAppliedGameIds: [] },
      },
      appliedTargets: null,
      appliedGameIds: ["deadlock"],
      regionStates: { "deadlock:eu": "blocked", "cs2:eu": "none" },
      appliedCount: 1,
      dirty: true,
    } as unknown as Status;
    expect(
      libraryGames(games, [], blockGameIds(status)).map((g) => g.id),
    ).toEqual(["cs2", "deadlock"]);
    expect(gameBlockState("deadlock", status)).toBe("blocked");
    expect(gameBlockState("cs2", status)).toBe("none");
    status.appliedCount = null;
    expect(gameBlockState("deadlock", status)).toBeUndefined();
    expect(gameBlockState("cs2", status)).toBeUndefined();
    status.appliedGameIds = [];
    status.appliedCount = 0;
    status.dirty = false;
    expect(gameBlockState("cs2", status)).toBe("none");
    status.snapshot.preferences.blockedRegions = [];
    expect(blockGameIds(status)).toEqual([]);
  });
  it("binary badges report actual block presence, not saved switches or attribution", () => {
    const status = {
      snapshot: { preferences: { blockedRegions: [], lastAppliedGameIds: [] } },
      appliedGameIds: [],
      appliedCount: 2,
      regionStates: { "deadlock:dxb": "blocked", "cs2:dxb": "partial" },
      dirty: true,
    } as unknown as Status;
    expect(gameBlockState("deadlock", status)).toBe("blocked");
    expect(gameBlockState("cs2", status)).toBe("blocked");
    status.regionStates = { "deadlock:dxb": "none", "cs2:dxb": "none" };
    status.appliedGameIds = ["deadlock"];
    expect(gameBlockState("deadlock", status)).toBe("none");
    expect(gameBlockState("cs2", status)).toBe("none");
    status.appliedCount = null;
    expect(gameBlockState("deadlock", status)).toBeUndefined();
  });
  it("hides launcher tools and retains chosen games when discovery no longer finds them", () => {
    const scan: Scan = {
      games: [
        {
          id: "steam-1493710",
          name: "Proton Experimental",
          launcher: "Steam",
          directory: "/tools/proton",
        },
        {
          id: "steam-228980",
          name: "Steamworks Common Redistributables",
          launcher: "Steam",
          directory: "/tools/common",
        },
        {
          id: "steam-123",
          name: "A real game",
          launcher: "Steam",
          directory: "/games/real",
        },
      ],
      warnings: [],
    };
    expect(
      libraryCandidates(games, scan, true, ["deadlock"]).map((g) => g.id),
    ).toEqual(["steam-123", "custom-mine", "deadlock"]);
    expect(
      libraryCandidates(games, scan, true, ["deadlock"]).find(
        (g) => g.id === "deadlock",
      )?.availability,
    ).toBe("Not found");
  });
  it("keeps last-applied games visible after restarting with unchecked regions", () => {
    const status = {
      snapshot: {
        preferences: { blockedRegions: [], lastAppliedGameIds: ["cs2"] },
      },
      appliedTargets: null,
      appliedGameIds: [],
      appliedCount: null,
      dirty: true,
    } as unknown as Status;
    expect(
      libraryGames(games, [], blockGameIds(status)).map((game) => game.id),
    ).toEqual(["cs2"]);
    expect(gameBlockState("cs2", status)).toBeUndefined();
  });
});

describe("locale files", () => {
  const locales: Locale[] = [
    {
      code: "en",
      name: "English",
      direction: "ltr",
      messages: { Games: "Games", count: "{name}: {count}" },
    },
    {
      code: "fr",
      name: "Français",
      direction: "ltr",
      messages: { Games: "Jeux" },
    },
    {
      code: "ar",
      name: "العربية",
      direction: "rtl",
      messages: { Games: "الألعاب" },
    },
  ];
  it("supports any JSON language and English fallback", () => {
    expect(translate(locales, "fr", "Games")).toBe("Jeux");
    expect(translate(locales, "fr", "Unknown")).toBe("Unknown");
    expect(translate(locales, "missing", "Games")).toBe("Games");
    expect(selectedLocale(locales, "ar")?.direction).toBe("rtl");
  });
  it("does not recursively expand variables or inherited property names", () => {
    expect(
      translate(locales, "fr", "count", { name: "{count}", count: 5 }),
    ).toBe("{count}: 5");
    expect(translate([], "en", "{toString}")).toBe("{toString}");
  });
});

describe("region selection", () => {
  it("preserves other games and deduplicates keys", () => {
    expect(toggleKeys(["other:a", "cs2:a"], ["cs2:a", "cs2:b"], true)).toEqual([
      "other:a",
      "cs2:a",
      "cs2:b",
    ]);
    expect(toggleKeys(["other:a", "cs2:a"], ["cs2:a"], false)).toEqual([
      "other:a",
    ]);
  });
  it("cannot block regions with no targets and reports partial selection", () => {
    const game = {
      id: "cs2",
      regions: [
        { id: "a", area: "Europe", endpoints: [{}] },
        { id: "b", area: "Europe", endpoints: [{}] },
        { id: "empty", area: "Europe", endpoints: [] },
      ],
    } as Game;
    const preferences = { blockedRegions: ["cs2:a"] } as Preferences;
    expect(areaSelection(game, "Europe", preferences)).toEqual({
      keys: ["cs2:a", "cs2:b"],
      selected: 1,
      checked: false,
    });
    expect(areaSelection(game, "Asia", preferences).checked).toBe(false);
  });
});
