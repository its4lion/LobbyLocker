import type { Locale } from "./types";

export function selectedLocale(
  locales: Locale[],
  code: string,
): Locale | undefined {
  return (
    locales.find((locale) => locale.code === code) ??
    locales.find((locale) => locale.code === "en")
  );
}

export function translate(
  locales: Locale[],
  code: string,
  key: string,
  values: Record<string, string | number> = {},
): string {
  const fallback = locales.find((locale) => locale.code === "en");
  const template =
    selectedLocale(locales, code)?.messages[key] ??
    fallback?.messages[key] ??
    key;
  // One pass, plain text only: substituted values cannot inject HTML or expand recursively.
  return template.replace(/\{([^{}]+)\}/g, (token, name: string) =>
    Object.hasOwn(values, name) ? String(values[name]) : token,
  );
}
