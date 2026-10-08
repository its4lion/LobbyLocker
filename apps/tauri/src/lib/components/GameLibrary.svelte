<script lang="ts">
  import { Button, buttonVariants } from "@lobbylocker/ui/components/button";
  import { Input } from "@lobbylocker/ui/components/input";
  import * as DropdownMenu from "@lobbylocker/ui/components/dropdown-menu";
  import { Search, Plus, Gamepad2, FolderOpen, File } from "@lucide/svelte";
  import GameArtwork from "./GameArtwork.svelte";
  import GameBlockBadge from "./GameBlockBadge.svelte";
  import type { Backend } from "$lib/backend.svelte";
  let {
    app,
    version,
    managing = false,
    onmanage,
    onfolder,
    onexecutable,
    onselect,
    onabout,
  }: {
    app: Backend;
    version: string;
    managing?: boolean;
    onmanage: () => void;
    onfolder: () => void;
    onexecutable: () => void;
    onselect: (id: string) => void;
    onabout: () => void;
  } = $props();
  let query = $state("");
  const games = $derived(app.games);
  const visible = $derived(
    games.filter((game) =>
      game.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()),
    ),
  );
</script>

<aside class="game-library" aria-label={app.t("Game library")}>
  <h2 class="font-semibold">{app.t("Games")}</h2>
  <div class="mt-5 flex gap-2">
    <div class="relative min-w-0 flex-1">
      <Search
        class="pointer-events-none absolute start-3 top-2.5 size-4 text-muted-foreground"
      /><Input
        class="ps-9"
        aria-label={app.t("Search games")}
        placeholder={app.t("Search games…")}
        bind:value={query}
      />
    </div>
    <DropdownMenu.Root>
      <DropdownMenu.Trigger
        class={buttonVariants({ variant: "outline", size: "icon" })}
        disabled={app.busy || !app.status}
        aria-label={app.t("Add a game")}
        ><Plus class="size-4" /></DropdownMenu.Trigger
      >
      <DropdownMenu.Content align="end">
        <DropdownMenu.Item onSelect={onfolder}
          ><FolderOpen />{app.t("Add library folder")}</DropdownMenu.Item
        >
        <DropdownMenu.Item onSelect={onexecutable}
          ><File />{app.t("Choose executable")}</DropdownMenu.Item
        >
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  </div>
  {#if games.length}
    <Button
      variant="ghost"
      size="sm"
      class="my-3 w-full text-muted-foreground"
      disabled={app.busy || managing}
      onclick={onmanage}>{app.t("Manage games")}</Button
    >
    <div class="flex-1 space-y-1">
      {#each visible as game (game.id)}
        <button
          type="button"
          class="library-game"
          class:active={game.id === app.selected}
          disabled={app.busy}
          aria-pressed={game.id === app.selected}
          onclick={() => onselect(game.id)}
        >
          <GameArtwork {app} id={game.id} />
          <span class="min-w-0 flex-1"
            ><span class="block truncate font-medium" dir="auto"
              >{game.name}</span
            ><span class="mt-1 flex flex-wrap items-center gap-1.5"
              ><GameBlockBadge {app} id={game.id} /></span
            ></span
          >
        </button>
      {:else}<p class="p-4 text-sm text-muted-foreground">
          {app.t("No games match your search.")}
        </p>{/each}
    </div>
  {:else}
    <div
      class="flex min-h-64 flex-1 flex-col items-center justify-center gap-4 py-10 text-center"
    >
      <Gamepad2 class="size-8 text-muted-foreground" />
      <p class="max-w-48 text-sm text-muted-foreground">
        {app.t(
          app.scanning ? "Detecting games…" : "Choose which games appear here.",
        )}
      </p>
      <Button
        variant="outline"
        disabled={app.busy || !app.status || managing}
        onclick={onmanage}>{app.t("Choose games")}</Button
      >
    </div>
  {/if}
  <button type="button" class="library-about" onclick={onabout}>
    <span class="font-medium" dir="ltr">LobbyLocker v{version}</span>
    <span>{app.t("Created by")} <b dir="ltr">its4lion</b></span>
  </button>
</aside>
