import { describe, expect, it } from "vitest";
import { gameArtwork, localIcon } from "./artwork";
import type { Scan } from "./types";

describe("local game icons", () => {
  const icon = "data:image/png;base64,aWNvbg==";
  const scan: Scan = {
    games: [
      {
        id: "deadlock",
        name: "Deadlock",
        launcher: "Steam",
        directory: "/games/deadlock",
      },
    ],
    warnings: [],
    icons: { deadlock: icon },
  };
  it("only shows scanned local icons for actual installations", () => {
    expect(gameArtwork("deadlock", scan, false)).toBeUndefined();
    expect(gameArtwork("deadlock", scan, true)).toBe(icon);
    expect(gameArtwork("cs2", scan, true)).toBeUndefined();
    expect(gameArtwork("unknown", scan, true)).toBeUndefined();
  });
  it("shows persisted custom executable icons without launching or scanning the game", () => {
    expect(
      gameArtwork("custom-game", scan, false, { "custom-game": icon }),
    ).toBe(icon);
  });
  it("never uses URLs, raw filesystem paths, SVGs, or oversized data", () => {
    for (const value of [
      "https://shared.fastly.steamstatic.com/icon.jpg",
      "file:///games/icon.png",
      "data:image/svg+xml;base64,abcd",
      `data:image/png;base64,${"a".repeat(200_000)}`,
    ])
      expect(localIcon(value)).toBeUndefined();
  });
});
