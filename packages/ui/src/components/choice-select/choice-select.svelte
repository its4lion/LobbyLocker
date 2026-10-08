<script lang="ts" generics="T extends string">
  import * as Select from "@lobbylocker/ui/components/select";
  let {
    value = $bindable(),
    options,
    id,
    ariaLabel,
    disabled = false,
    placeholder = "",
    class: className = "w-full",
    onValueChange,
  }: {
    value: T;
    options: { value: T; label: string }[];
    id?: string;
    ariaLabel?: string;
    disabled?: boolean;
    placeholder?: string;
    class?: string;
    onValueChange?: (value: T) => unknown | Promise<unknown>;
  } = $props();
  let selected = $state("");
  $effect(() => {
    selected = value;
  });
  const label = $derived(
    options.find((option) => option.value === selected)?.label ?? placeholder,
  );
  async function change(next: string) {
    if (next === value) return;
    if (onValueChange) {
      try {
        await onValueChange(next as T);
      } finally {
        selected = value;
      }
    } else {
      value = next as T;
    }
  }
</script>

<Select.Root
  type="single"
  bind:value={selected}
  {disabled}
  onValueChange={change}
>
  <Select.Trigger {id} aria-label={ariaLabel} class={className}
    ><span class="truncate" dir="auto">{label}</span></Select.Trigger
  >
  <Select.Content>
    {#each options as option (option.value)}<Select.Item
        value={option.value}
        label={option.label}><span dir="auto">{option.label}</span></Select.Item
      >{/each}
  </Select.Content>
</Select.Root>
