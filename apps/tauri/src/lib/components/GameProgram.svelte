<script lang="ts">
  import { Button } from "@lobbylocker/ui/components/button";
  import { FolderOpen } from "@lucide/svelte";
  import type { Backend } from "$lib/backend.svelte";
  import type { Game } from "$lib/types";
  let { app, game }: { app: Backend; game: Game } = $props();
</script>

<div class="mb-5 rounded-lg border p-4" data-game-program>
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div class="min-w-0 flex-1">
      <h2 class="font-medium">{app.t("Windows per-app blocking")}</h2>
      {#if game.executablePath}<code class="mt-2">{game.executablePath}</code>
      {:else}<p class="mt-2 text-sm text-muted-foreground">
          {app.t(
            "Choose this game's actual .exe before Apply. System-wide fallback is not allowed.",
          )}
        </p>{/if}
    </div>
    <Button
      variant="outline"
      disabled={app.busy}
      onclick={() => app.command("set_game_executable", { gameId: game.id })}
      ><FolderOpen />{app.t(
        game.executablePath ? "Change executable" : "Choose executable",
      )}</Button
    >
  </div>
  <p class="mt-3 text-xs text-muted-foreground">
    {app.t(
      "Apply will filter only this exact executable. Launchers and child executables are not automatically included. Changing the path takes effect after Apply; the file is never launched.",
    )}
  </p>
</div>
