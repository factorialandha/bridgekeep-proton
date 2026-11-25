import { useState } from "react"
import { Link, useSearchParams } from "react-router"
import { Ban, Check, ChevronRight, ShieldAlert, ShieldCheck, Trash2, Undo2 } from "lucide-react"
import { api, ApiError, type LogEntryData, type UnsubscribeResult } from "@/api"
import { useApi } from "@/useApi"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Failed, Loading, PageHeader, Unavailable } from "./common"
import { Result } from "./Log"

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 px-4 py-3 sm:grid-cols-[10rem_1fr] sm:gap-4">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

export function LogEntryPage() {
  const [params] = useSearchParams()
  const id = params.get("id") ?? ""
  const { data, error, reload } = useApi<LogEntryData>(`/api/log/entry?id=${encodeURIComponent(id)}`)
  const [fail, setFail] = useState("")
  const crumbs = <p className="mb-1 text-sm text-muted-foreground"><Link to="/log" className="hover:underline">Log</Link> / Entry</p>

  if (error?.status === 404 || error?.status === 400)
    return <div className="max-w-3xl">{crumbs}<PageHeader title="Not found" lead="That entry may have been removed by the log's retention limit." /></div>
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  if (data.unavailable) return <div className="max-w-3xl">{crumbs}<PageHeader title="Log entry" /><Unavailable /></div>

  const { row: r, verdict, unsub } = data
  const answer = (v: "keep" | "trash" | "undo") => {
    setFail("")
    api.post("/api/review/verdict", { id: r.id, verdict: v }).then(reload, (e: ApiError) => setFail(e.message))
  }
  const sender = encodeURIComponent(r.from_addr)

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        {crumbs}
        <PageHeader title={r.subject === null ? "(subject not stored)" : r.subject || "(no subject)"}>
          <Result r={r} />
          {verdict && <Badge variant="secondary">You: {verdict === "keep" ? "not spam" : "spam"}</Badge>}
        </PageHeader>
      </div>

      <Card className="gap-0 py-0">
        <dl className="divide-y">
          <Row label="From"><span className="font-mono text-sm">{r.from_addr}</span></Row>
          <Row label="Received"><time dateTime={new Date(r.ts * 1000).toISOString()}>{r.full_when}</time></Row>
          <Row label="Why">{r.why || r.explain}</Row>
          <Row label="The AI said">
            {r.label ? (
              <>
                {r.label}{r.confidence !== null && `, ${Math.round(r.confidence * 100)}% sure`}
                {r.reason && <span className="block text-sm text-muted-foreground">“{r.reason}”</span>}
              </>
            ) : <span className="text-muted-foreground">Not asked (a rule decided first)</span>}
          </Row>
          <Row label="Authentication">
            {r.verified
              ? <Badge variant="outline" className="text-success"><ShieldCheck /> DMARC verified</Badge>
              : <Badge variant="outline" className="border-warning/40 text-warning"><ShieldAlert /> Not verified</Badge>}
          </Row>
          {r.injections.length > 0 && (
            <Row label="Injection flag">
              <Badge variant="outline" className="border-destructive/40 text-destructive"><Ban /> Text aimed at AI filters</Badge>
              <ul className="mt-2 space-y-1">{r.injections.map((t, i) => <li key={i} className="rounded-md bg-muted px-2 py-1 font-mono text-xs break-all">{t}</li>)}</ul>
            </Row>
          )}
          {r.error && <Row label="Error"><span className="font-mono text-sm">{r.error}</span></Row>}
        </dl>
      </Card>

      <Card className="gap-4">
        <CardHeader>
          <CardTitle>{r.action === "review" ? "Spam or not?" : "Was this right?"}</CardTitle>
          <CardDescription>
            {r.action === "review" ? "The analyzer wasn't sure about this one." : "If the analyzer got this wrong, tell it."}{" "}
            Your answer teaches it: after two “Not spam” answers for a sender whose mail is signed, and no “Spam” answers, it won't trash their mail any more. At most it asks you.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <Button variant={verdict === "keep" ? "default" : "outline"} aria-pressed={verdict === "keep"} onClick={() => answer("keep")}><Check /> Not spam</Button>
            <Button variant={verdict === "trash" ? "default" : "outline"} aria-pressed={verdict === "trash"} onClick={() => answer("trash")}><Trash2 /> Spam</Button>
            {verdict && <Button variant="ghost" onClick={() => answer("undo")}><Undo2 /> Clear my answer</Button>}
          </div>
          {fail && <p role="alert" className="text-sm text-destructive">{fail}</p>}
          {verdict && <p className="text-xs text-muted-foreground">Clearing removes your answer and what the analyzer learned from it. Mail already decided stays as it is.</p>}
          {r.from_addr && (
            <p className="flex flex-wrap items-center gap-x-1 text-sm">
              <span className="text-muted-foreground">This sender:</span>
              <Button asChild variant="link" size="sm" className="px-1"><Link to={`/lists?add=protect&value=${sender}`}>Never trash</Link></Button>
              <span aria-hidden="true" className="text-muted-foreground">·</span>
              <Button asChild variant="link" size="sm" className="px-1"><Link to={`/lists?add=block&value=${sender}`}>Always trash</Link></Button>
            </p>
          )}
        </CardContent>
      </Card>

      {unsub && (
        <Card className="gap-4" id="unsubscribe">
          <CardHeader>
            <CardTitle>Unsubscribe</CardTitle>
            <CardDescription>
              {unsub.method === "one_click"
                ? <>This sender offers a one-click unsubscribe at <span className="font-mono">{unsub.host}</span> that Bridgekeep checked is safe to use. You'll confirm before anything is sent.</>
                : "Bridgekeep never sends mail for you. To unsubscribe, send an email from your mail app to:"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {unsub.method === "one_click" ? (
              <UnsubscribeDialog id={r.id} host={unsub.host} sender={r.from_addr} />
            ) : <code className="block rounded-md bg-muted px-3 py-2 font-mono text-sm break-all">{unsub.mailto}</code>}
          </CardContent>
        </Card>
      )}

      <Collapsible>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="group -ml-2 text-muted-foreground"><ChevronRight className="transition-transform group-data-[state=open]:rotate-90" /> Decision record</Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <Card className="mt-2 gap-0 py-0">
            <dl className="divide-y font-mono text-xs">
              {([["Rule", r.rule], ["Mode", r.mode], ["Model", r.model], ["Prompt version", r.prompt_version], ["Message key", r.key]] as const).map(([k, v]) => (
                <Row key={k} label={k}>{v || "–"}</Row>
              ))}
            </dl>
          </Card>
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}

/** One-click unsubscribe: confirm, then the portal's unsubscribe service calls the sender's link once. */
function UnsubscribeDialog({ id, host, sender }: { id: number; host: string; sender: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [out, setOut] = useState<UnsubscribeResult | null>(null)
  const [err, setErr] = useState("")
  const send = () => {
    setErr(""); setBusy(true)
    api.post<UnsubscribeResult>("/api/unsubscribe", { id, confirm: true }).then(setOut, (e: ApiError) => setErr(e.message)).finally(() => setBusy(false))
  }
  const h = out?.host || host
  return (
    <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) { setOut(null); setErr("") } }}>
      <DialogTrigger asChild><Button variant="outline">Unsubscribe…</Button></DialogTrigger>
      <DialogContent>
        {!out ? <>
          <DialogHeader>
            <DialogTitle>Unsubscribe from this sender?</DialogTitle>
            <DialogDescription>
              Bridgekeep will use the sender's one-click unsubscribe link once, on your behalf. It contacts <span className="font-mono">{h}</span>, the address named in the sender's own message (Bridgekeep checked it matches the sender's signature), and sends nothing about you except that request.
            </DialogDescription>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">From <span className="font-mono break-all">{sender}</span>. Some senders take a few days to stop.</p>
          {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={send} disabled={busy}>Unsubscribe</Button>
          </DialogFooter>
        </> : <>
          <DialogHeader>
            <DialogTitle>{out.result === "done" ? "Unsubscribed" : out.result === "refused" ? "Not sent" : "That didn't work"}</DialogTitle>
            <DialogDescription role={out.result === "done" ? "status" : "alert"}>
              {out.result === "done" ? <><span className="font-mono">{h}</span> accepted the request.</>
                : out.result === "refused" ? `Bridgekeep didn't send it: ${(out.detail || "the link didn't pass its safety checks").replace(/\.$/, "")}.`
                : out.detail || "The sender's server didn't accept the request."}
            </DialogDescription>
          </DialogHeader>
          {out.result !== "done" && <p className="text-sm text-muted-foreground">{out.result === "refused"
            ? "You can use the unsubscribe link in the message from your mail app instead."
            : "You can try again later, or use the unsubscribe link in the message from your mail app."}</p>}
          <DialogFooter><Button onClick={() => setOpen(false)}>Close</Button></DialogFooter>
        </>}
      </DialogContent>
    </Dialog>
  )
}
