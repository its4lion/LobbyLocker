<script lang="ts">
  import { Gamepad2 } from "@lucide/svelte";
  import { gameArtwork } from "$lib/artwork";
  import type { Backend } from "$lib/backend.svelte";
  let {
    app,
    id,
    large = false,
  }: { app: Backend; id: string; large?: boolean } = $props();
  const source = $derived(
    gameArtwork(id, app.installed, app.scanned, app.customIcons),
  );
  let failed = $state(false);
  $effect(() => {
    source;
    app.installed;
    failed = false;
  });
</script>

<span
  class={`flex shrink-0 items-center justify-center overflow-hidden rounded-lg bg-muted ${large ? "size-14" : "size-10"}`}
  aria-hidden="true"
>
  {#if source && !failed}
    <img
      src={source}
      alt=""
      loading="lazy"
      referrerpolicy="no-referrer"
      class="size-full object-contain p-1"
      onerror={() => (failed = true)}
    />
  {:else}<Gamepad2
      class={large
        ? "size-6 text-muted-foreground"
        : "size-4 text-muted-foreground"}
    />{/if}
</span>
