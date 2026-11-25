export type Theme = "system" | "light" | "dark"
const KEY = "bk-theme"
export function getTheme(): Theme {
  try { return (localStorage.getItem(KEY) as Theme) || "system" } catch { return "system" }
}
export function applyTheme(t: Theme) {
  const dark = t === "dark" || (t === "system" && matchMedia("(prefers-color-scheme: dark)").matches)
  document.documentElement.classList.toggle("dark", dark)
  document.documentElement.style.colorScheme = dark ? "dark" : "light"
}
export function setTheme(t: Theme) {
  try { localStorage.setItem(KEY, t) } catch { /* private mode */ }
  applyTheme(t)
}
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(getTheme()))
