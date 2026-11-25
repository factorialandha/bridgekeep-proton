import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { Info, Pause, Send } from "lucide-react"
import { api, ApiError, type LiveData } from "@/api"
import { useApi } from "@/useApi"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Failed, Loading, PageHeader } from "./common"

const n = (v: number | null | undefined) => (v ?? 0).toLocaleString()

export function AnalyzerLivePage() {
  const { data, error } = useApi<LiveData>("/api/analyzer/live")
  const nav = useNavigate()
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)

  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  const l = data.live
  const a = l.agreement
  const go = () => {
    setErr(""); setBusy(true)
    api.post("/api/analyzer/mode", { mode: "live", confirm: true }).then(
      () => nav("/analyzer?done=live"),
      (x: ApiError) => { setErr(x.message); setBusy(false) })
  }

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <p className="mb-1 text-sm text-muted-foreground"><Link to="/analyzer" className="hover:underline">Analyzer</Link> / Live mode</p>
        <PageHeader title="Switch to live mode?" />
      </div>

      {!data.available ? (
        <Alert><Info /><AlertTitle>Live mode isn't available yet</AlertTitle>
          <AlertDescription>This version of the analyzer can only log what it would do.</AlertDescription></Alert>
      ) : <>
        <Alert><Info /><AlertTitle>Only new mail moves</AlertTitle>
          <AlertDescription>It goes into AI-Review and AI-Quarantine in Proton. Nothing is deleted. Marking a message Not spam moves it back.</AlertDescription></Alert>

        <ul className="list-disc space-y-1.5 pl-5 text-sm">
          <li>Nothing goes to Proton's Trash and nothing is deleted. In Bridgekeep, "Trash" means the AI-Quarantine folder. Nothing is marked read, and older mail (including a backfill) never moves.</li>
          <li>Senders on Never trash are never moved.</li>
          {l.move_cap != null && <li>At most {n(l.move_cap)} moves a day. If it reaches that, moves stop and you get a Discord alert.</li>}
          <li>You get a Discord alert whenever the mode changes.</li>
        </ul>

        <section className="space-y-3">
          <h2 className="text-base font-semibold">How shadow mode went</h2>
            <dl className="divide-y rounded-lg border text-sm">
              {l.shadow_since != null && <Row label="In shadow since">{new Date(l.shadow_since * 1000).toLocaleDateString()}</Row>}
              <Row label="Would have moved">{l.would_review != null || l.would_quarantine != null
                ? `${n(l.would_review)} to AI-Review, ${n(l.would_quarantine)} to AI-Quarantine` : "Not reported yet"}</Row>
              <Row label="Your answers">{a?.corrections
                ? `Of ${n(a.corrections)} answers, the analyzer agreed with ${n(a.model_agreed)}. It called ${n(a.said_spam_was_fine)} good messages spam and missed ${n(a.missed_spam)} spam.`
                : <>None yet. Answering "Was this right?" on a few <Link to="/log" className="text-primary hover:underline">Log</Link> entries shows how well it would do.</>}</Row>
            </dl>
        </section>

        {data.paused && (
          <Alert><Pause /><AlertTitle>The analyzer is paused</AlertTitle>
            <AlertDescription>Live mode starts when you resume it.</AlertDescription></Alert>
        )}
        <p className="text-sm text-muted-foreground">You can switch back to shadow mode at any time with one click, and the Log shows every move.</p>
        {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
        <div className="flex flex-wrap gap-2">
          <Button onClick={go} disabled={busy}><Send /> Switch to live</Button>
          <Button asChild variant="ghost"><Link to="/analyzer">Cancel</Link></Button>
        </div>
      </>}
    </div>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 px-4 py-2.5 sm:grid-cols-[9rem_1fr] sm:gap-3">
      <dt className="text-muted-foreground">{label}</dt><dd className="min-w-0">{children}</dd>
    </div>
  )
}
