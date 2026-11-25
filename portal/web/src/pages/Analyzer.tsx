import { useEffect, useMemo, useState } from "react"
import { ChevronRight, KeyRound, Eye, Info, Send } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { api, ApiError, type AnalyzerData } from "@/api"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useApi } from "@/useApi"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Slider } from "@/components/ui/slider"
import { Progress } from "@/components/ui/progress"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog"
import { Failed, Loading, PageHeader, Section } from "./common"

type S = AnalyzerData["settings"]

export function AnalyzerPage() {
  const { data, error, reload } = useApi<AnalyzerData>("/api/analyzer")
  const [s, setS] = useState<S | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const nav = useNavigate()
  const [params] = useSearchParams()
  useEffect(() => { if (data) setS(data.settings) }, [data])
  const dirty = useMemo(() => data && s && JSON.stringify(s) !== JSON.stringify(data.settings), [data, s])
  const would = useMemo(() => {
    if (!data || !s) return { trash: 0, review: 0 }
    const q = s["thresholds.quarantine"] / 100, r = s["thresholds.review"] / 100
    return {
      trash: data.preview.scores.filter((x) => x >= q).length,
      review: data.preview.scores.filter((x) => x >= r && x < q).length,
    }
  }, [data, s])
  if (error) return <Failed error={error} />
  if (!data || !s) return <Loading />
  const set = <K extends keyof S>(k: K, v: S[K]) => setS({ ...s, [k]: v })
  const num = (k: keyof S) => (e: React.ChangeEvent<HTMLInputElement>) => set(k, Number(e.target.value) as never)

  const save = () => api.post("/api/analyzer/settings", s).then(
    () => { setMsg({ ok: true, text: "Saved. The analyzer uses the new settings from its next check." }); reload() },
    (e: ApiError) => setMsg({ ok: false, text: e.message }),
  )

  const unsaved = data.unsaved ?? []
  const spendPct = data.spend != null && data.budget ? Math.min(100, (data.spend / data.budget) * 100) : null

  return (
    <div className="max-w-4xl pb-20">
      <PageHeader title="Analyzer" lead="How the analyzer decides, what it may spend on the AI, and how often it checks for mail." />
      {params.get("done") === "live" && !msg && <p role="status" className="mb-4 text-sm text-success">Live mode is on. New mail now moves into AI-Review and AI-Quarantine; switch back to shadow here at any time.</p>}
      {msg && <p role="status" className={msg.ok ? "mb-4 text-sm text-success" : "mb-4 text-sm text-destructive"}>{msg.text}</p>}
      {unsaved.length > 0 && !dirty && (
        <Alert className="mb-6"><Info /><AlertTitle>These settings aren't saved in the portal yet</AlertTitle>
          <AlertDescription>
            <p>Until they are, the analyzer uses its own setup file{unsaved.includes("model.monthly_budget_usd") ? ", and the budget below is the one it uses now" : ""}. Save once so the portal keeps them and you can change them here.</p>
            <Button size="sm" className="mt-2" onClick={save} disabled={!data.writable}>Save as shown</Button>
          </AlertDescription></Alert>
      )}

      <Section title="Mode" description="Shadow only logs what it would do. Live moves mail into AI-Review and AI-Quarantine.">
        <ToggleGroup type="single" variant="outline" value={data.mode} aria-label="Mode"
          onValueChange={(v) => { if (v === "shadow" && data.mode !== "shadow") api.post("/api/analyzer/mode", { mode: "shadow" }).then(reload); if (v === "live") nav("/analyzer/live") }}>
          <ToggleGroupItem value="shadow" className="px-4"><Eye /> Shadow</ToggleGroupItem>
          <ToggleGroupItem value="live" className="px-4" disabled={!data.live_available}><Send /> Live</ToggleGroupItem>
        </ToggleGroup>
        {!data.live_available && <p className="text-sm text-muted-foreground">Live isn't available in this version yet. Until then, your Not spam / Spam answers show how it would do.</p>}
      </Section>

      <Section title="AI" description="Which AI reads the extracted fields of new mail, and what it costs.">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-medium">{data.vendor_label}</span>
          {data.model_name && <Badge variant="secondary" className="font-mono">{data.model_name}</Badge>}
          <Button asChild variant="link" size="sm" className="px-1"><Link to="/analyzer/vendor">Change</Link></Button>
        </div>
        {spendPct != null && (
          <div className="max-w-md">
            <div className="mb-1.5 flex justify-between text-sm"><span>This month</span>
              <span className="tabular-nums"><span className="font-semibold">${data.spend!.toFixed(2)}</span> of ${data.budget}</span></div>
            <Progress value={spendPct} aria-label="AI spend against budget" />
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <KeyRound className="size-4 text-muted-foreground" aria-hidden="true" />
          {data.key.on ? <span>API key set, ending <code className="font-mono">…{data.key.last4}</code></span>
            : <span className="text-muted-foreground">No API key yet. Only your lists and rules decide.</span>}
          <KeyDialog on={data.key.on} onDone={reload} />
        </div>
      </Section>

      <Section title="Spending">
        <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
          <div>
            <Label htmlFor="ai-on">Use the AI</Label>
            <p className="mt-1 text-sm text-muted-foreground">{s["model.enabled"]
              ? `On: when your lists and rules don't decide, the extracted fields of new mail are sent to ${data.vendor_label} to score it.`
              : `Off: only your lists and the built-in rules decide. No mail is sent to ${data.vendor_label}.`}</p>
          </div>
          <Switch id="ai-on" checked={s["model.enabled"]} onCheckedChange={(v) => set("model.enabled", v)} />
        </div>
        <div className="grid max-w-xs gap-2">
          <Label htmlFor="budget" className="flex items-center gap-2">Monthly budget (US$)
            {unsaved.includes("model.monthly_budget_usd") && <Badge variant="outline" className="font-normal">not saved yet</Badge>}</Label>
          <Input id="budget" type="number" inputMode="numeric" min={0} max={1000} step={1} value={s["model.monthly_budget_usd"]} onChange={num("model.monthly_budget_usd")} />
          <p className="text-sm text-muted-foreground">When it's reached, rules only until the 1st.</p>
        </div>
      </Section>

      <Section title="How strict" description="How sure the AI must be before mail is trashed or sent to Review.">
        <Threshold id="q" label="Trash when the AI is this sure it's spam" value={s["thresholds.quarantine"]} min={50} max={100}
          onChange={(v) => set("thresholds.quarantine", v)} hint="Default 97." />
        <Threshold id="r" label="Send to Review when it's this sure" value={s["thresholds.review"]} min={30} max={100}
          onChange={(v) => set("thresholds.review", v)} hint="Default 70. Must be lower than Trash." />
        {data.preview.checked > 0 && (
          <p className="rounded-lg border-l-4 border-l-primary bg-muted/60 px-4 py-3 text-sm" aria-live="polite">
            Last 14 days at these settings: of {data.preview.checked} messages the AI scored, <strong className="tabular-nums">{would.trash}</strong> would
            be trashed and <strong className="tabular-nums">{would.review}</strong> sent to Review.
          </p>
        )}
      </Section>

      <Section title="Advanced">
        <Collapsible>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="group -ml-3 text-muted-foreground">
              <ChevronRight className="transition-transform group-data-[state=open]:rotate-90" /> Limits and how often it checks
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-3 grid gap-4 sm:grid-cols-2">
            <NumField id="ph" label="AI checks per hour, at most" value={s["limits.max_per_hour"]} onChange={num("limits.max_per_hour")} hint="Default 120." />
            <NumField id="pd" label="AI checks per day, at most" value={s["limits.max_per_day"]} onChange={num("limits.max_per_day")} hint="Default 1,000." />
            <NumField id="mv" label="Mail moves a day in live mode" value={s["limits.max_moves_per_day"]} onChange={num("limits.max_moves_per_day")} hint="Default 200. 0 never moves mail." />
            <NumField id="poll" label="Check for new mail every (seconds)" value={s["imap.poll_seconds"]} onChange={num("imap.poll_seconds")} hint="Default 60." />
          </CollapsibleContent>
        </Collapsible>
      </Section>

      <Section title="Older mail" description="Mail from before setup is left alone unless you ask.">
        <Button asChild variant="outline" className="w-fit"><Link to="/backfill">Estimate the cost of analyzing it</Link></Button>
      </Section>

      <div className={`fixed inset-x-0 bottom-16 z-20 border-t bg-background/95 px-4 py-3 backdrop-blur transition md:bottom-0 md:left-56 ${dirty ? "translate-y-0" : "pointer-events-none translate-y-full opacity-0"}`}>
        <div className="mx-auto flex max-w-4xl items-center justify-end gap-2">
          <span className="mr-auto text-sm text-muted-foreground">You have unsaved changes.</span>
          <Button variant="ghost" onClick={() => setS(data.settings)}>Undo</Button>
          <Button onClick={save} disabled={!data.writable}>Save</Button>
        </div>
      </div>
    </div>
  )
}

function Threshold({ id, label, value, min, max, onChange, hint }: {
  id: string; label: string; value: number; min: number; max: number; onChange: (v: number) => void; hint: string
}) {
  return (
    <div className="grid max-w-lg gap-3">
      <div className="flex items-baseline justify-between gap-3">
        <Label id={`${id}-l`}>{label}</Label>
        <span className="text-lg font-semibold tabular-nums">{value}%</span>
      </div>
      <Slider aria-labelledby={`${id}-l`} min={min} max={max} step={1} value={[value]} onValueChange={([v]) => onChange(v)} />
      <p className="text-sm text-muted-foreground">{hint}</p>
    </div>
  )
}

function NumField({ id, label, value, onChange, hint }: {
  id: string; label: string; value: number; onChange: (e: React.ChangeEvent<HTMLInputElement>) => void; hint: string
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} type="number" inputMode="numeric" value={value} onChange={onChange} />
      <p className="text-xs text-muted-foreground">{hint}</p>
    </div>
  )
}

function KeyDialog({ on, onDone }: { on: boolean; onDone: () => void }) {
  const [open, setOpen] = useState(false)
  const [key, setKey] = useState("")
  const [err, setErr] = useState("")
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    api.post("/api/secrets/set", { name: "anthropic_api_key", value: key }).then(
      () => { setKey(""); setOpen(false); onDone() },
      (x: ApiError) => setErr(x.message),
    )
  }
  return (
    <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) { setKey(""); setErr("") } }}>
      <DialogTrigger asChild><Button variant="outline" size="sm">{on ? "Replace" : "Add a key"}</Button></DialogTrigger>
      <DialogContent>
        <form onSubmit={submit} autoComplete="off">
          <DialogHeader>
            <DialogTitle>{on ? "Replace the API key" : "Add an API key"}</DialogTitle>
            <DialogDescription>Make a key just for Bridgekeep, with a spend limit. The portal never shows it again: the host installs it and keeps only the last 4 characters.</DialogDescription>
          </DialogHeader>
          <div className="my-4 grid gap-2">
            <Label htmlFor="key">Key</Label>
            <Input id="key" type="password" spellCheck={false} maxLength={220} placeholder="sk-ant-…" value={key} onChange={(e) => setKey(e.target.value)} required />
            {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
          </div>
          <DialogFooter><Button type="submit">Save the key</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
