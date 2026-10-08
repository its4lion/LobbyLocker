<script lang="ts">
  import { onMount } from "svelte";
  import packageInfo from "../package.json";
  import { Backend } from "$lib/backend.svelte";
  import { actionBar, applyReview } from "$lib/action-bar";
  import { scopeWarning, missingPrograms } from "$lib/firewall";
  import * as Tabs from "@lobbylocker/ui/components/tabs";
  import * as AlertDialog from "@lobbylocker/ui/components/alert-dialog";
  import { Button } from "@lobbylocker/ui/components/button";
  import { ChoiceSelect } from "@lobbylocker/ui/components/choice-select";
  import { Gamepad2, Check, LoaderCircle, Moon, Sun } from "@lucide/svelte";
  import GameLibrary from "$lib/components/GameLibrary.svelte";
  import ManageGames from "$lib/components/ManageGames.svelte";
  import CustomGame from "$lib/components/CustomGame.svelte";
  import Regions from "$lib/components/Regions.svelte";
  import Connections from "$lib/components/Connections.svelte";
  import Settings from "$lib/components/Settings.svelte";
  import AboutDialog from "$lib/components/AboutDialog.svelte";
  const app = new Backend();
  const version = packageInfo.version;
  let page = $state("Regions");
  let view = $state<"main" | "manage" | "custom">("main");
  let customPath = $state("");
  let content = $state<HTMLDivElement | null>(null);
  let confirmOpen = $state(false);
  let aboutOpen = $state(false);
  let dark = $state(true);
  const pages = ["Regions", "Connections", "Settings"];
  const direction = $derived(app.locale?.direction ?? "ltr");
  const bar = $derived(actionBar(app.status, app.busy));
  const review = $derived(applyReview(app.status));
  const missing = $derived(missingPrograms(app.status));
  const footerId = $props.id();
  const applySummary = `${footerId}-summary`;
  const applyWarning = `${footerId}-warning`;
  const feedback = $derived(
    app.firewallAction
      ? app.firewallSlow
        ? "Still waiting for administrator approval or the firewall helper. No new request has been sent."
        : app.firewallAction === "apply"
          ? "Applying… Check the administrator prompt."
          : app.firewallAction === "read"
            ? "Reading firewall… Administrator access may be requested. No rules will be changed."
            : "Resetting… Check the administrator prompt."
      : app.firewallFeedback === "apply"
        ? "Firewall changes applied."
        : app.firewallFeedback === "reset"
          ? "LobbyLocker blocks removed."
          : app.firewallFeedback === "error"
            ? "Firewall operation not confirmed. Review the error above."
            : app.busy
              ? "Working…"
              : bar.apply
                ? review.regions
                  ? app.status?.verification === "different"
                    ? "apply_review_different"
                    : "apply_review"
                  : "Apply will remove all LobbyLocker blocks."
                : bar.key,
  );
  onMount(() => {
    void app.initialize().then(() => {
      if (app.status && !app.games.length) view = "manage";
    });
  });
  $effect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = app.locale?.code ?? "en";
    document.documentElement.classList.toggle("dark", dark);
  });
  $effect(() => {
    view;
    page;
    app.selected;
    content?.scrollTo({ top: 0 });
  });
  function manage() {
    app.error = "";
    view = "manage";
  }
  async function addFolder() {
    if (await app.addLibrary()) manage();
  }
  async function addExecutable() {
    const path = await app.pickExecutable();
    if (path) {
      customPath = path;
      view = "custom";
    }
  }
  function showGame(id?: string) {
    if (id) app.selected = id;
    view = "main";
    page = "Regions";
    app.error = "";
  }
  async function apply() {
    if (!(await app.command("apply_rules"))) content?.scrollTo({ top: 0 });
  }
  async function reset() {
    confirmOpen = false;
    if (!(await app.command("reset_rules"))) content?.scrollTo({ top: 0 });
  }
</script>

<Tabs.Root
  bind:value={page}
  dir={direction}
  class="app-shell"
  onValueChange={() => (view = "main")}
>
  <header class="topbar">
    <div class="flex items-center gap-2 font-semibold">
      <Gamepad2 class="size-5" /><span dir="ltr">LobbyLocker</span>
    </div>
    <Tabs.List aria-label={app.t("Main navigation")} class="h-auto flex-wrap"
      >{#each pages as item}<Tabs.Trigger
          value={item}
          onclick={() => (view = "main")}>{app.t(item)}</Tabs.Trigger
        >{/each}</Tabs.List
    >
    <div class="flex items-center gap-2">
      <ChoiceSelect
        class="w-32"
        ariaLabel={app.t("Language")}
        placeholder={app.t("Language")}
        disabled={app.busy || !app.status}
        value={app.code}
        options={app.languages.locales.map((locale) => ({
          value: locale.code,
          label: locale.name,
        }))}
        onValueChange={(code) => app.command("set_language", { code })}
      /><Button
        variant="ghost"
        size="icon"
        aria-label={app.t("Toggle theme")}
        onclick={() => (dark = !dark)}
        >{#if dark}<Sun />{:else}<Moon />{/if}</Button
      >
    </div>
  </header>
  <div class="workspace">
    <main class="main-panel" dir={direction}>
      <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard users must be able to focus and scroll this region.) -->
      <div
        class="content"
        bind:this={content}
        aria-busy={app.busy}
        role="region"
        aria-label={app.t("Main content")}
        tabindex="0"
      >
        {#if app.error}<div
            role="alert"
            class="mb-5 rounded-lg border border-destructive p-4 text-sm text-destructive"
            dir="auto"
          >
            {app.t(app.error)}
          </div>{/if}
        {#if app.firewallError}<div
            role="alert"
            data-firewall-error
            class="mb-5 rounded-lg border border-destructive p-4 text-sm"
          >
            <p class="text-destructive">
              {app.t(
                "Could not read firewall status. Existing blocks have not been changed by this check.",
              )}
            </p>
            <details class="mt-2 text-xs text-muted-foreground">
              <summary>{app.t("Error details")}</summary>
              <p class="mt-2" dir="auto">{app.firewallError}</p>
            </details>
            <Button
              class="mt-3"
              size="sm"
              variant="outline"
              disabled={app.busy}
              onclick={() => app.readFirewall()}>{app.t("Retry")}</Button
            >
          </div>{/if}
        {#if app.status}
          {#if view === "manage"}<ManageGames
              {app}
              ondone={() => showGame()}
              oncancel={() => (view = "main")}
              onfolder={addFolder}
              onexecutable={addExecutable}
            />
          {:else if view === "custom"}{#key customPath}<CustomGame
                {app}
                path={customPath}
                ondone={() => showGame()}
                oncancel={() => (view = "main")}
              />{/key}
          {:else}
            <Tabs.Content value="Regions"
              ><Regions {app} onmanage={manage} /></Tabs.Content
            >
            <Tabs.Content value="Connections"
              ><Connections {app} /></Tabs.Content
            >
            <Tabs.Content value="Settings"
              ><Settings
                {app}
                onreset={() => (confirmOpen = true)}
                onmanage={manage}
              /></Tabs.Content
            >
          {/if}
        {:else if app.busy}<p class="empty" role="status">
            {app.t("Working…")}
          </p>{:else}<Button variant="outline" onclick={() => app.initialize()}
            >{app.t("Retry")}</Button
          >{/if}
      </div>
      {#if bar.visible || app.firewallAction || app.firewallFeedback}<footer
          class="footerbar"
        >
          <div class="min-w-0 flex-1">
            <p
              id={applySummary}
              role={app.firewallFeedback === "error" ? "alert" : "status"}
              title={review.games.join(", ")}
            >
              {app.t(feedback, {
                ...bar.values,
                games: review.games.length,
                regions: review.regions,
              })}
            </p>
            {#if bar.apply || app.firewallAction === "apply"}<p
                id={applyWarning}
                class="mt-1 max-w-2xl text-xs text-muted-foreground"
              >
                {app.t(scopeWarning(app.status))}
              </p>{/if}
            {#if bar.apply && missing.length}<p
                class="mt-1 text-xs text-destructive"
              >
                {app.t("Choose executables for these games before Apply")}:
                <span dir="auto"
                  >{missing.map((target) => target.gameName).join(", ")}</span
                >
              </p>{/if}
          </div>
          {#if bar.apply || app.firewallAction === "apply"}<div
              class="flex gap-2"
            >
              <Button
                data-action="apply"
                aria-describedby={`${applySummary}${bar.apply ? ` ${applyWarning}` : ""}`}
                disabled={app.busy || !bar.apply || missing.length > 0}
                onclick={apply}
                >{#if app.firewallAction === "apply"}<LoaderCircle
                    class="animate-spin"
                  />{:else}<Check />{/if}{app.t(
                  app.firewallAction === "apply" ? "Applying…" : "Apply",
                )}</Button
              >
            </div>{/if}
        </footer>{/if}
    </main>
    <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard users must be able to focus and scroll this region.) -->
    <div
      class="library-panel"
      dir={direction}
      role="region"
      aria-label={app.t("Game library")}
      tabindex="0"
    >
      <GameLibrary
        {app}
        {version}
        managing={view === "manage"}
        onmanage={manage}
        onfolder={addFolder}
        onexecutable={addExecutable}
        onselect={showGame}
        onabout={() => (aboutOpen = true)}
      />
    </div>
  </div>
</Tabs.Root>
<AlertDialog.Root bind:open={confirmOpen}>
  <AlertDialog.Content
    ><AlertDialog.Header
      ><AlertDialog.Title>{app.t("Reset")}</AlertDialog.Title
      ><AlertDialog.Description
        >{app.t(
          "Remove only LobbyLocker-owned firewall rules? Other firewall rules are untouched.",
        )}</AlertDialog.Description
      ></AlertDialog.Header
    ><AlertDialog.Footer
      ><AlertDialog.Cancel>{app.t("Cancel")}</AlertDialog.Cancel
      ><AlertDialog.Action disabled={app.busy} onclick={reset}
        >{app.t("Reset")}</AlertDialog.Action
      ></AlertDialog.Footer
    ></AlertDialog.Content
  >
</AlertDialog.Root>
<AboutDialog {app} {version} bind:open={aboutOpen} />
