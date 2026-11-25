// Supply-chain and code rules for the portal frontend, run in CI (portal-web).
//   node check.mjs
// 1. package-lock.json v3: every package comes from registry.npmjs.org with an
//    integrity hash (no git, URL or file dependencies).
// 2. package.json pins exact versions.
// 3. The source never uses dangerouslySetInnerHTML, eval, new Function, HTML
//    string sinks or javascript: URLs (skipped with --lock-only, in the image build).
// 4. With --dist: the build holds none of the dev-only demo data.
import { readFileSync, readdirSync, statSync } from "node:fs"
import { join } from "node:path"

const problems = []
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"))
if (lock.lockfileVersion !== 3) problems.push(`lockfileVersion is ${lock.lockfileVersion}, expected 3`)
for (const [name, p] of Object.entries(lock.packages)) {
  if (name === "" || p.link || p.inBundle) continue   // inBundle: inside its parent's tarball, covered by its integrity
  if (!p.resolved?.startsWith("https://registry.npmjs.org/")) problems.push(`${name}: resolved from ${p.resolved}`)
  if (!p.integrity?.startsWith("sha512-")) problems.push(`${name}: no sha512 integrity`)
}
const pkg = JSON.parse(readFileSync("package.json", "utf8"))
for (const [name, v] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
  if (!/^\d+\.\d+\.\d+$/.test(v)) problems.push(`package.json: ${name} is "${v}", not an exact version`)
}
const banned = /dangerouslySetInnerHTML|\beval\s*\(|new\s+Function\s*\(|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write|srcdoc|javascript:/i
function walk(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f)
    if (statSync(p).isDirectory()) walk(p)
    else if (/\.(tsx?|jsx?)$/.test(f) && !/\.test\.ts$/.test(f)) {   // tests hold the bad strings on purpose
      readFileSync(p, "utf8").split("\n").forEach((line, i) => {
        if (banned.test(line)) problems.push(`${p}:${i + 1}: ${line.trim()}`)
      })
    }
  }
}
if (!process.argv.includes("--lock-only")) walk("src")
// The demo data (src/demo.ts) must never reach a build.
if (process.argv.includes("--dist")) {
  const dist = "../src/portal/web_dist"
  const marker = "lambdanetsllc.example"
  ;(function scan(d) {
    for (const f of readdirSync(d)) {
      const p = join(d, f)
      if (statSync(p).isDirectory()) scan(p)
      else if (readFileSync(p, "utf8").includes(marker)) problems.push(`${p}: contains demo data`)
    }
  })(dist)
}
if (problems.length) {
  console.error(problems.join("\n"))
  process.exit(1)
}
console.log(`ok: ${Object.keys(lock.packages).length - 1} locked packages, source clean`)
