# Shared UI

CLI-installed **shadcn-svelte** components for LobbyLocker apps. No Tauri APIs,
game logic, or app-specific layouts belong here. `packages/theme` is removed;
shared tokens and bundled fonts live in `src/styles.css`.

In a Svelte 5 + Tailwind 4 app, add `"@lobbylocker/ui": "workspace:*"` and import:

```svelte
<script lang="ts">
  import { Button } from "@lobbylocker/ui/components/button";
  import * as Dialog from "@lobbylocker/ui/components/dialog";
</script>

<Button>Continue</Button>
```

```css
@import "@lobbylocker/ui/styles.css";
```

Configure the app's Tailwind 4 Vite plugin. The shared CSS registers its own
component sources with `@source "."`; app classes are detected by the app build.
Set `dir` and `lang` on the document so portal content follows the chosen locale.
Add `.dark` to the document element for the dark theme.

`@lobbylocker/ui/components/select` contains the CLI-generated shadcn Select.
`@lobbylocker/ui/components/choice-select` adds a typed `ChoiceSelect` wrapper
for simple `{ value, label }` option lists. Use `bind:value` for form fields or
`onValueChange` for asynchronous authoritative updates. Options render in a
themed, keyboard-accessible portal rather than an operating-system dropdown.

Add components using the official CLI from the repository root:

```sh
pnpm --filter @lobbylocker/ui ui:add tooltip
pnpm --filter @lobbylocker/ui check
```

The package's `components.json` and TypeScript aliases route generated components
and utilities here, not into a consuming app. CLI-generated `.js` import paths
have matching exports resolving to the TypeScript source. Upstream MIT notices
are retained in the root `LICENSE`. There is no website app yet.
