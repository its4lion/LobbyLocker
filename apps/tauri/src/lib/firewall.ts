import type { FirewallTarget, Status } from "./types";

export function windowsBlocking(status: Status | null): boolean {
  return status?.snapshot.platform === "windows";
}

export function scopeWarning(status: Status | null): string {
  return windowsBlocking(status)
    ? "Applies only to each selected game executable on Windows. Rules remain active after closing LobbyLocker."
    : "Applies system-wide. Shared ranges can affect other apps; rules remain active after closing LobbyLocker.";
}

export function missingPrograms(status: Status | null): FirewallTarget[] {
  if (!windowsBlocking(status)) return [];
  const seen = new Set<string>();
  return savedTargets(status).filter((target) => {
    if (target.executablePath?.trim() || seen.has(target.gameId)) return false;
    seen.add(target.gameId);
    return true;
  });
}

/** Current saved choices are a preview, never a substitute for applied state. */
export function savedTargets(status: Status | null): FirewallTarget[] {
  if (!status) return [];
  const selected = new Set(status.snapshot.preferences.blockedRegions);
  return status.snapshot.games.flatMap((game) =>
    game.regions
      .filter(
        (region) =>
          region.endpoints.length && selected.has(`${game.id}:${region.id}`),
      )
      .map((region) => ({
        gameId: game.id,
        gameName: game.name,
        regionId: region.id,
        regionName: region.name,
        executablePath: windowsBlocking(status)
          ? (game.executablePath ?? null)
          : null,
        endpoints: region.endpoints,
      })),
  );
}

export function filterTargets(
  targets: FirewallTarget[],
  query: string,
): FirewallTarget[] {
  const search = query.trim().toLowerCase();
  if (!search) return targets;
  return targets.flatMap((target) => {
    if (
      `${target.gameName} ${target.regionName} ${target.executablePath ?? ""}`
        .toLowerCase()
        .includes(search)
    )
      return [target];
    const endpoints = target.endpoints.filter((endpoint) =>
      `${endpoint.address} ${endpoint.protocol} ${endpoint.ports ?? ""}`
        .toLowerCase()
        .includes(search),
    );
    return endpoints.length ? [{ ...target, endpoints }] : [];
  });
}
