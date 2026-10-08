<script lang="ts">
  import * as Card from "@lobbylocker/ui/components/card";
  import * as AlertDialog from "@lobbylocker/ui/components/alert-dialog";
  import { Button } from "@lobbylocker/ui/components/button";
  import { scopeWarning } from "$lib/firewall";
  import type { Backend } from "$lib/backend.svelte";
  let {
    app,
    onreset,
    onmanage,
  }: { app: Backend; onreset: () => void; onmanage: () => void } = $props();
  let adminOpen = $state(false);

  async function restartAsAdmin() {
    adminOpen = false;
    await app.command("restart_as_admin");
  }
</script>

<div class="page-heading">
  <div>
    <h1>{app.t("Settings")}</h1>
    <p>{app.t("Local files, game data, and firewall recovery.")}</p>
  </div>
</div>
<div class="grid gap-5 xl:grid-cols-2">
  <Card.Root
    ><Card.Header
      ><Card.Title>{app.t("Local game files")}</Card.Title><Card.Description
        >{app.t(
          "Each game is stored in a separate JSON file. Existing files are never overwritten on startup.",
        )}</Card.Description
      ></Card.Header
    ><Card.Content class="space-y-4"
      ><code>{app.status?.snapshot.configDir}</code>
      <div class="flex flex-wrap gap-3">
        <Button
          variant="outline"
          disabled={app.busy}
          onclick={() => app.importGame()}>{app.t("Import game JSON")}</Button
        ><Button
          variant="outline"
          disabled={app.busy || !app.game}
          onclick={() => app.command("export_game", { gameId: app.selected })}
          >{app.t("Export selected game")}</Button
        >
      </div></Card.Content
    ></Card.Root
  >
  {#if app.status?.snapshot.platform === "windows"}<Card.Root
      ><Card.Header
        ><Card.Title>{app.t("Administrator session")}</Card.Title
        ><Card.Description
          >{app.t(
            "Optionally restart LobbyLocker with administrator privileges for this session.",
          )}</Card.Description
        ></Card.Header
      ><Card.Content class="space-y-3"
        ><Button
          variant="outline"
          disabled={app.busy}
          onclick={() => (adminOpen = true)}
          >{app.t("Restart as administrator")}</Button
        >
        <p class="text-xs leading-relaxed text-muted-foreground">
          {app.t(
            "This can reduce repeated permission prompts, but the entire application will be elevated until you close it. Startup settings are not changed.",
          )}
        </p></Card.Content
      ></Card.Root
    >{/if}
  {#if app.status?.selfUpdateSupported}<Card.Root
      ><Card.Header
        ><Card.Title>{app.t("Updates")}</Card.Title><Card.Description
          >{app.t(
            "LobbyLocker checks for signed updates when it opens. Installation always requires your confirmation.",
          )}</Card.Description
        ></Card.Header
      ><Card.Content class="space-y-3">
        {#if app.updateVersion}<p class="text-sm">
            {app.t("update_available", { version: app.updateVersion })}
          </p>
          {#if app.updateNotes}<p
              class="text-xs whitespace-pre-line text-muted-foreground"
              dir="auto"
            >
              {app.updateNotes}
            </p>{/if}
          <Button
            disabled={app.busy || app.updateInstalling}
            onclick={() => app.installUpdate()}
            >{app.t(
              app.updateInstalling ? "Installing update…" : "Install update",
            )}</Button
          >{:else}<p class="text-sm text-muted-foreground">
            {app.t(
              app.updateChecking
                ? "Checking for updates…"
                : app.updateChecked
                  ? "LobbyLocker is up to date."
                  : "Updates have not been checked yet.",
            )}
          </p>
          <Button
            variant="outline"
            disabled={app.busy || app.updateChecking}
            onclick={() => app.checkForUpdates()}
            >{app.t("Check for updates")}</Button
          >{/if}
        {#if app.updateError}<p class="text-xs text-destructive" dir="auto">
            {app.updateError}
          </p>{/if}
      </Card.Content></Card.Root
    >{/if}
  <Card.Root
    ><Card.Header
      ><Card.Title>{app.t("Game library folders")}</Card.Title><Card.Description
        >{app.t(
          "Default and added library folders are listed together. Removing a folder stops discovery there, not blocking or deleting files.",
        )}</Card.Description
      ></Card.Header
    ><Card.Content class="space-y-4">
      {#each app.libraryFolders as folder (folder.path)}<div
          class="flex items-center gap-3"
          data-library-path={folder.path}
        >
          <div class="min-w-0 flex-1">
            <code>{folder.path}</code>
            <p class="mt-1 text-xs text-muted-foreground">
              {app.t(folder.source)}
            </p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            disabled={app.busy}
            onclick={() => app.removeLibrary(folder.path)}
            >{app.t("Remove")}</Button
          >
        </div>{:else}<p class="text-sm text-muted-foreground">
          {app.t(
            app.scanning
              ? "Detecting games…"
              : "No library folders configured.",
          )}
        </p>{/each}
      <Button
        variant="outline"
        disabled={app.busy}
        onclick={() => app.addLibrary()}>{app.t("Add library folder")}</Button
      >
      <Button variant="ghost" disabled={app.busy} onclick={onmanage}
        >{app.t("Manage games")}</Button
      >
      {#if app.installed.warnings.length}<details>
          <summary>{app.t("Scan warnings")}</summary
          >{#each app.installed.warnings as warning}<p
              class="mt-2 text-xs text-muted-foreground"
              dir="auto"
            >
              {warning}
            </p>{/each}
        </details>{/if}
    </Card.Content></Card.Root
  >
  <Card.Root
    ><Card.Header
      ><Card.Title>{app.t("Firewall recovery")}</Card.Title><Card.Description
        >{app.t(
          "Only LobbyLocker-owned firewall rules are removed. Other firewall rules are untouched.",
        )}</Card.Description
      ></Card.Header
    ><Card.Content
      ><Button variant="destructive" disabled={app.busy} onclick={onreset}
        >{app.t("Reset")}</Button
      >
      <p class="mt-4 text-xs text-muted-foreground">
        {app.t(scopeWarning(app.status))}
      </p>
      {#if app.status}<details class="mt-4 text-xs text-muted-foreground">
          <summary>{app.t("Status details")}</summary>
          <p class="mt-2" dir="auto">{app.t(app.status.message)}</p>
        </details>{/if}</Card.Content
    ></Card.Root
  >
</div>

<AlertDialog.Root bind:open={adminOpen}>
  <AlertDialog.Content>
    <AlertDialog.Header>
      <AlertDialog.Title>{app.t("Restart as administrator?")}</AlertDialog.Title
      >
      <AlertDialog.Description>
        {app.t(
          "Windows will show a User Account Control prompt. The web interface, server-data requests, file dialogs, and firewall operations will all run with administrator privileges for this session.",
        )}
      </AlertDialog.Description>
    </AlertDialog.Header>
    <AlertDialog.Footer>
      <AlertDialog.Cancel>{app.t("Cancel")}</AlertDialog.Cancel>
      <AlertDialog.Action disabled={app.busy} onclick={restartAsAdmin}
        >{app.t("Restart")}</AlertDialog.Action
      >
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
