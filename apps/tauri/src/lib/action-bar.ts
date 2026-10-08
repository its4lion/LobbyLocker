import type { Status } from "./types";

/** A loaded catalogue is not a pending firewall action. Keep the idle UI quiet. */
export function actionBar(
  status: Status | null,
  busy: boolean,
): {
  visible: boolean;
  apply: boolean;
  key: string;
  values: Record<string, number>;
} {
  if (!status) return { visible: false, apply: false, key: "", values: {} };
  const preferences = status.snapshot.preferences;
  const selections = new Set([...preferences.blockedRegions]).size;
  return {
    visible: status.dirty || (status.appliedCount ?? 0) > 0,
    apply: status.dirty,
    key: busy
      ? "Working…"
      : status.dirty
        ? "pending_changes_count"
        : "active_rules_count",
    values: { count: status.dirty ? selections : (status.appliedCount ?? 0) },
  };
}

/** Review configured, nonempty regions only; unknown/empty saved keys cannot
 * produce firewall targets. Shared ranges still apply system-wide. */
export function applyReview(status: Status | null) {
  const selected = new Set([
    ...(status?.snapshot.preferences.blockedRegions ?? []),
  ]);
  const games: string[] = [];
  let regions = 0;
  for (const game of status?.snapshot.games ?? []) {
    const count = game.regions.filter(
      (region) =>
        region.endpoints.length > 0 && selected.has(`${game.id}:${region.id}`),
    ).length;
    if (count) {
      games.push(game.name);
      regions += count;
    }
  }
  return { games, regions };
}
