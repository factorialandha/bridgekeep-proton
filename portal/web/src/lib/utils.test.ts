// node --test src/lib/utils.test.ts  (Node 22 strips the types)
import { test } from "node:test"
import assert from "node:assert/strict"
import { safeHref } from "./utils.ts"

const o = "https://pi.local:8443"
test("same-origin paths pass, normalised", () => {
  assert.equal(safeHref("/app/review", o), "/app/review")
  assert.equal(safeHref("/lists?add=protect#x", o), "/lists?add=protect#x")
})
test("tricks that leave the site are refused", () => {
  for (const bad of ["//evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil.example", "\\\\evil.example",
    "javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "http://evil.example", " javascript:x"]) {
    assert.equal(safeHref(bad, o), "#", JSON.stringify(bad))
  }
})
test("https links stay", () => {
  assert.equal(safeHref("https://console.anthropic.com/settings/keys", o), "https://console.anthropic.com/settings/keys")
})
