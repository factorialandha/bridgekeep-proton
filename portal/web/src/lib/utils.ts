import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** Only same-origin paths and https: links may come from data (security review).
 * Browsers read "\\" as "/" and drop tabs and newlines, so "/\\evil.example" is
 * another site: resolve first, then compare origins. */
export function safeHref(href: string | null | undefined, origin: string = globalThis.location?.origin ?? "http://localhost"): string {
  if (!href) return "#"
  let u: URL
  try {
    u = new URL(href, origin)
  } catch {
    return "#"
  }
  if (u.origin === origin) return u.pathname + u.search + u.hash
  return u.protocol === "https:" && /^https:\/\//i.test(href.trim()) ? u.href : "#"
}
