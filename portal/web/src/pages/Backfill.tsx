import { useEffect, useState } from "react"
import { Link } from "react-router"
import { CircleAlert, Hourglass, Info, Pause, Play, X } from "lucide-react"
import { api, ApiError, type BackfillData, type BackfillJob } from "@/api"
import { useApi } from "@/useApi"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import { Failed, Loading, PageHeader } from "./common"

const n = (v: number) => v.toLocaleString()
const usd = (v: number) => `$${v.toFixed(2)}`

export function BackfillPage() {
  const { data, error, reload } = useApi<BackfillData>("/api/backfill")
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null)
  const busy = Boolean(data && (data.pending || (data.job && ["estimating", "running"].includes(data.job.status))))
  // While the analyzer works on a request, check again every 30 seconds.
  useEffect(() => {
    if (!busy) return
    const t = setInterval(reload, 30000)
    return () => clearInterval(t)
  }, [busy, reload])

  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  const j = data.job
  const send = (path: string, body: unknown, ok: string) => {
    setNote(null)
    return api.post(path, body).then(
      () => { setNote({ ok: true, text: ok }); reload(); return true },
      (e: ApiError) => { setNote({ ok: false, text: e.message }); return false })
  }
  const sent = "Sent. The analyzer acts on it at its next check."

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <p className="mb-1 text-sm text-muted-foreground"><Link to="/analyzer" className="hover:underline">Analyzer</Link> / Older mail</p>
        <PageHeader title="Older mail" lead="The analyzer only looks at mail that arrives after setup. To have it look at older mail, get a cost estimate first, then start it. Like everything else it's log-only: it records what it would do and moves nothing." />
      </div>

      {note && <p role={note.ok ? "status" : "alert"} className={note.ok ? "text-sm text-success" : "text-sm text-destructive"}>{note.text}</p>}
      {!data.writable && (
        <Alert variant="destructive"><CircleAlert /><AlertTitle>The portal can't save requests yet</AlertTitle>
          <AlertDescription>Its settings folder isn't set up. Run ./bridgekeep setup on the host.</AlertDescription></Alert>
      )}
      {data.pending && (
        <Alert><Hourglass /><AlertTitle>Waiting for the analyzer</AlertTitle>
          <AlertDescription>It picks up your last request at its next check. This page updates by itself.</AlertDescription></Alert>
      )}

      {j?.status === "estimating" && (
        <Card className="gap-4">
          <CardHeader><CardTitle>Estimating</CardTitle>
            <CardDescription>Reading headers only. Nothing is sent anywhere while it estimates.</CardDescription></CardHeader>
          <CardContent className="space-y-3">
            {j.candidates > 0 && <Progress value={(100 * j.scanned) / j.candidates} aria-label="Headers read" />}
            <p className="text-sm tabular-nums">{n(j.scanned)}{j.candidates > 0 && ` of ${n(j.candidates)}`} read</p>
            <Button variant="ghost" disabled={data.pending} onClick={() => send("/api/backfill/cancel", {}, sent)}><X /> Cancel</Button>
          </CardContent>
        </Card>
      )}

      {j?.status === "estimated" && data.stale && (
        <Alert><Info /><AlertTitle>The last estimate is more than a day old</AlertTitle>
          <AlertDescription>It can't be started. Estimate again below.</AlertDescription></Alert>
      )}
      {j?.status === "estimated" && !data.stale && <Estimate data={data} job={j} onStart={(partial) =>
        send("/api/backfill/start", { estimate_id: j.id, provider: data.provider, allow_partial: partial }, "Started. Progress shows here.")} />}

      {(j?.status === "running" || j?.status === "paused") && (
        <Card className="gap-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">{j.status === "running" ? "Running" : "Paused"}
              <Badge variant="outline" className="tabular-nums">{n(j.processed)} of {n(j.selected)}</Badge></CardTitle>
            <CardDescription>{n(j.model_calls)} sent to {data.vendor} · {usd(j.spend_usd)} so far{j.reason && ` · ${j.reason}`}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Progress value={j.selected ? (100 * j.processed) / j.selected : 0} aria-label="Messages done" />
            <div className="flex flex-wrap gap-2">
              {j.status === "running"
                ? <Button disabled={data.pending} onClick={() => send("/api/backfill/pause", {}, sent)}><Pause /> Pause</Button>
                : <Button disabled={data.pending} onClick={() => send("/api/backfill/resume", {}, sent)}><Play /> Resume</Button>}
              <Button variant="ghost" disabled={data.pending} onClick={() => send("/api/backfill/cancel", {}, sent)}><X /> Cancel for good</Button>
              <Button asChild variant="link"><Link to="/log">See what it decided in the log</Link></Button>
            </div>
          </CardContent>
        </Card>
      )}

      {j?.status === "done" && (
        <p role="status" className="text-sm">The last backfill finished: {n(j.processed)} messages, {usd(j.spend_usd)}. <Link to="/log" className="text-primary hover:underline">See it in the log</Link>.</p>
      )}
      {j?.status === "cancelled" && (
        <p className="text-sm text-muted-foreground">The last backfill was cancelled{j.reason && j.reason !== "cancelled on request" ? `: ${j.reason}` : ""}.</p>
      )}

      {(!j || ["estimated", "paused", "done", "cancelled"].includes(j.status)) && (
        <EstimateForm data={data} again={j?.status === "estimated" || j?.status === "paused"} onSend={(body) => send("/api/backfill/estimate", body,
          "Asked for an estimate. The analyzer reads only the headers, and the numbers show here within a few minutes.")} />
      )}
    </div>
  )
}

function Estimate({ data, job: j, onStart }: { data: BackfillData; job: BackfillJob; onStart: (partial: boolean) => void }) {
  const [ok, setOk] = useState(false)
  const partial = !j.fits_budget
  return (
    <Card className="gap-4">
      <CardHeader><CardTitle>Estimate ready</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        <Alert><Info /><AlertDescription>{data.disclosure}</AlertDescription></Alert>
        <dl className="divide-y rounded-lg border text-sm">
          {[
            ["Dates", `${j.since || "The oldest message"} to ${j.until || "setup"}${j.limit ? `, at most ${n(j.limit)} messages` : ""}`],
            ["Estimated cost", `About ${usd(j.est_usd)} with ${data.vendor}`],
            ["Budget left this month", `${usd(j.budget_left_usd)} of $${Math.round(j.budget_usd)} (10% is kept for new mail)`],
            ["How long", `${j.est_hours < 1 ? "Under an hour" : `About ${j.est_hours} hour${j.est_hours === 1 ? "" : "s"}`}. New mail always goes first.`],
          ].map(([k, v]) => (
            <div key={k} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[12rem_1fr]"><dt className="text-muted-foreground">{k}</dt><dd>{v}</dd></div>
          ))}
        </dl>
        {j.reason && <p role="alert" className="text-sm text-destructive">The analyzer didn't start it: {j.reason}.</p>}
        {partial && (
          <div className="space-y-2">
            <p className="text-sm">That's more than the budget left this month. About {n(j.calls_that_fit)} of the {n(j.est_calls)} messages fit. It stops there and carries on next month, or you can narrow the dates below.</p>
            <div className="flex items-start gap-2">
              <Checkbox id="partial" checked={ok} onCheckedChange={(v) => setOk(v === true)} />
              <Label htmlFor="partial" className="font-normal">Start anyway, and stop when this month's budget is used</Label>
            </div>
          </div>
        )}
        <p className="text-xs text-muted-foreground">Starting asks for your password if you haven't confirmed it in the last 5 minutes. You can pause or cancel at any time.</p>
        <Button disabled={data.pending || !data.writable || (partial && !ok)} onClick={() => onStart(partial)}><Play /> Start</Button>
      </CardContent>
    </Card>
  )
}

function EstimateForm({ data, again, onSend }: { data: BackfillData; again: boolean; onSend: (b: { since: string; until: string; limit: string }) => Promise<boolean> }) {
  const [f, setF] = useState({ since: "", until: "", limit: "" })
  const warn = {
    off: <>The AI is off, so the backfill would only use your lists and rules. Turn it on under <Link className="text-primary hover:underline" to="/analyzer">Analyzer</Link> first.</>,
    no_key: <>There's no API key for {data.vendor}, so the backfill would only use your lists and rules. {data.provider === "anthropic"
      ? <Link className="text-primary hover:underline" to="/analyzer">Add a key</Link> : <a className="text-primary hover:underline" href="/analyzer/vendor">Add a key</a>} first.</>,
    no_price: <>The model has no prices yet, so the backfill would only use your lists and rules. <a className="text-primary hover:underline" href="/analyzer/vendor">Add prices</a> first.</>,
  }[data.model_state]
  return (
    <Card className="gap-4">
      <CardHeader><CardTitle>{again ? "Estimate again" : "Get an estimate"}</CardTitle>
        <CardDescription>Newest first. The estimate reads only headers and sends nothing anywhere.</CardDescription></CardHeader>
      <CardContent>
        {warn && <p className="mb-4 text-sm text-warning">{warn}</p>}
        <form className="grid gap-4 sm:grid-cols-3" onSubmit={(e) => { e.preventDefault(); onSend(f).then((done) => { if (done) setF({ since: "", until: "", limit: "" }) }) }}>
          <div className="grid gap-1.5"><Label htmlFor="bf-since">From <span className="font-normal text-muted-foreground">(optional)</span></Label>
            <Input id="bf-since" type="date" value={f.since} onChange={(e) => setF({ ...f, since: e.target.value })} /></div>
          <div className="grid gap-1.5"><Label htmlFor="bf-until">To <span className="font-normal text-muted-foreground">(optional)</span></Label>
            <Input id="bf-until" type="date" value={f.until} onChange={(e) => setF({ ...f, until: e.target.value })} /></div>
          <div className="grid gap-1.5"><Label htmlFor="bf-limit">At most <span className="font-normal text-muted-foreground">(messages)</span></Label>
            <Input id="bf-limit" inputMode="numeric" maxLength={7} placeholder="All" value={f.limit} onChange={(e) => setF({ ...f, limit: e.target.value })} /></div>
          <p className="text-xs text-muted-foreground sm:col-span-3">Empty dates mean from the oldest message, up to setup.</p>
          <Button type="submit" className="w-fit" disabled={data.pending || !data.writable}>Estimate the cost</Button>
        </form>
      </CardContent>
    </Card>
  )
}
