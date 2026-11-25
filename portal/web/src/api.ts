// JSON API client. Same origin only; writes carry the CSRF token in a header.
// The server decides everything that matters (sessions, step-up, validation).
import { demo } from "./demo"

export type Session = {
  signed_in: boolean
  csrf: string
  product: string
  mode: "shadow" | "live"
  totp_on: boolean
  review_waiting: number
  versions: { bridgekeep: string; commit: string; portal: string; portal_commit?: string; portal_stale?: boolean; bridge: string }
}

export type Need = { level: "bad" | "todo"; text: string; how?: string; href?: string; action?: string }

export type StatusData = {
  summary: { ok: boolean; headline: string }
  needs: Need[]
  glance: { bridge: string; bridge_ok: boolean; messages: number | null; spend: number | null; budget: number | null; disk_free: string | null; disk_used_pct: number | null }
  details: { label: string; rows: { label: string; value: string; tone?: "ok" | "warn" | "bad" | "muted" }[] }[]
}

export type ReviewItem = {
  id: number
  from_addr: string
  subject: string | null
  ts: number
  when: string
  confidence: number | null
  label: string | null
  reason: string | null
  explain: string
}

export type AnalyzerData = {
  mode: "shadow" | "live"
  live_available: boolean
  vendor: string
  vendor_label: string
  model_name: string
  spend: number | null
  budget: number | null
  key: { on: boolean; last4: string; pending: boolean; when: number | null }
  /** Settings keys the portal hasn't saved yet: the analyzer uses its own config for them. */
  unsaved?: string[]
  settings: {
    "model.enabled": boolean
    "model.monthly_budget_usd": number
    "thresholds.quarantine": number
    "thresholds.review": number
    "limits.max_per_hour": number
    "limits.max_per_day": number
    "limits.max_moves_per_day": number
    "imap.poll_seconds": number
  }
  preview: { checked: number; scores: number[] }
  writable: boolean
}

export type LogRow = {
  id: number
  from_addr: string
  subject: string | null
  ts: number
  when: string
  full_when: string
  action: "quarantine" | "review" | "keep"
  applied: boolean
  moved_to: string | null
  moved_back: boolean
  why: string
  verdict: "" | "keep" | "trash"
}

export type LogEntry = LogRow & {
  key: string
  explain: string
  label: string | null
  confidence: number | null
  reason: string | null
  verified: boolean
  injections: string[]
  error: string | null
  rule: string
  mode: string
  model: string | null
  prompt_version: string | null
}

export type LogEntryData = {
  row: LogEntry
  verdict: "" | "keep" | "trash"
  unsub: { method: "one_click"; host: string } | { method: "mailto"; mailto: string } | null
  unavailable?: string
}

export type BackfillJob = {
  id: string
  status: "estimating" | "estimated" | "running" | "paused" | "done" | "cancelled"
  since: string
  until: string
  limit: number
  scanned: number
  candidates: number
  selected: number
  est_calls: number
  est_usd: number
  budget_left_usd: number
  budget_usd: number
  est_hours: number
  processed: number
  model_calls: number
  spend_usd: number
  calls_that_fit: number
  fits_budget: boolean
  estimated: boolean
  finished: number
  reason: string
  /** The AI vendor the job was started for. */
  provider?: string
}

export type BackfillData = {
  job: BackfillJob | null
  pending: boolean
  provider: string
  vendor: string
  stale: boolean
  model_state: string
  writable: boolean
  disclosure: string
}

export type LogData = {
  rows: LogRow[]
  card: { seen: number; quarantine: number; review: number; protected: number; answered: number } | null
  filters: { key: string; label: string }[]
  older: string | null
  /** Set (with empty data) when the analyzer's database can't be read yet. */
  unavailable?: string
}

export type ReviewData = { items: ReviewItem[]; unavailable?: string }

export type ListEntry = {
  index: number
  value: string
  kind: "address" | "domain" | "pattern"
  subdomains: boolean
  reason: string
  expires: string
  added: string
  source: "portal" | "file"
}

export type ListsData = {
  lists: { key: "protect" | "block" | "keywords"; label: string; help: string; field: string; entries: ListEntry[] }[]
  problems: { text: string; list: string; index: number; value: string; fix: string }[]
  removed: { list: string; label: string; value: string }[]
  writable: boolean
}

export type SecretState = { on: boolean; last4: string; pending: boolean; when: number | null; when_text: string; result: string }

export type SettingsData = {
  lan: boolean
  urls: string[]
  fingerprint: string[]
  port: number
  totp_on: boolean
  min_password: number
  totp_secret: string | null
  alerts: SecretState
  test_alert: { pending: boolean; result: string }
  alerts_writable: boolean
}

export type AuditData = { rows: { id: number; when: string; action: string; target: string; ip: string; result: string }[] }

export interface VendorFields { provider: string; model: string; endpoint: string; price_in: string; price_out: string }
export interface VendorData {
  current: { provider: string; label: string; model: string }
  vendors: Record<string, { label: string; model_hint: string; key_placeholder: string; needs_price: boolean }>
  state: { pending: boolean; when: number | null; result: string }
  drop_writable: boolean
  no_price: boolean
}
export interface VendorReview { fields: VendorFields; label: string; disclosure: string; key_placeholder: string; current_provider: string }
export interface LiveData {
  available: boolean
  paused: boolean
  live: {
    shadow_since?: number | null; would_review?: number | null; would_quarantine?: number | null; move_cap?: number | null
    agreement?: { corrections?: number; model_agreed?: number; said_spam_was_fine?: number; missed_spam?: number } | null
  }
}

export interface UnsubscribeResult { result: "done" | "refused" | "failed"; detail: string; host: string }

export interface ProtonStatus {
  available: boolean
  state: "" | "signed_out" | "signing_in" | "waiting_2fa" | "waiting_mailbox_password" | "waiting_human" | "signed_in" | "error"
  account: string
  error: string
  hv_url: string
  step_expires: number | null
  mail_paused: boolean
}

export class ApiError extends Error {
  status: number
  stepUp: boolean
  /** The error reply's JSON body, for endpoints that send more than `error`. */
  data: Record<string, unknown>
  constructor(status: number, message: string, stepUp = false, data: Record<string, unknown> = {}) {
    super(message)
    this.status = status
    this.stepUp = stepUp
    this.data = data
  }
}

let csrf = ""
export const setCsrf = (t: string) => { csrf = t }
export const getCsrf = () => csrf

// Step-up: the server answers 401 {"step_up": true}; the shell shows the
// password dialog, the server re-checks, and the write is sent once more.
type StepUpPrompt = () => Promise<boolean>
let stepUpPrompt: StepUpPrompt | null = null
export const onStepUp = (fn: StepUpPrompt | null) => { stepUpPrompt = fn }

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (import.meta.env.DEV && demo.has(path)) return demo.get(path) as T
  const r = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: method === "GET" ? { Accept: "application/json" }
      : { Accept: "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = await r.json().catch(() => ({}))
  if (r.status === 401 && data.signed_out) {
    // The session ended (expired, or signed out in another tab): back to sign-in.
    window.location.assign("/login")
    throw new ApiError(401, "You've been signed out.")
  }
  if (!r.ok) throw new ApiError(r.status, data.error || "Something went wrong.", Boolean(data.step_up), data)
  return data as T
}

// A write refused by the CSRF check (403) usually means the session or its
// token changed in another tab. Fetch the session again (which sends a
// signed-out browser to sign-in) and retry once with the fresh token.
async function refreshSession(): Promise<boolean> {
  try {
    const s = await call<{ signed_in?: boolean; csrf: string }>("GET", "/api/session")
    if (s.signed_in === false) {
      window.location.assign("/login")
      return false
    }
    if (!s.csrf || s.csrf === csrf) return false
    csrf = s.csrf
    return true
  } catch {
    return false
  }
}

async function write<T>(path: string, body: unknown): Promise<T> {
  try {
    return await call<T>("POST", path, body)
  } catch (e) {
    if (e instanceof ApiError && e.stepUp && stepUpPrompt && (await stepUpPrompt())) return call<T>("POST", path, body)
    if (e instanceof ApiError && e.status === 403 && (await refreshSession())) return call<T>("POST", path, body)
    throw e
  }
}

export const api = {
  get: <T,>(path: string) => call<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => write<T>(path, body),
  reauth: (password: string, code: string) => call<{ ok: true }>("POST", "/api/reauth", { password, code }),
}
