import type { Scan } from "./types";

/** Only renderer-safe, backend-produced PNG data is accepted. No file:// access,
 * user-provided URLs, remote CDN requests, or active SVG content. */
export function localIcon(
  source: string | null | undefined,
): string | undefined {
  return source &&
    source.length <= 200_000 &&
    /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/.test(source)
    ? source
    : undefined;
}

export function gameArtwork(
  id: string,
  scan: Scan,
  scanned: boolean,
  customIcons: Record<string, string> = {},
): string | undefined {
  const custom = localIcon(customIcons[id]);
  if (custom) return custom;
  if (!scanned || !scan.games.some((game) => game.id === id)) return undefined;
  return localIcon(scan.icons?.[id]);
}
