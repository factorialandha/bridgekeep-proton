import { useState } from "react"
import { Link } from "react-router"
import { CircleAlert, Hourglass, Info, ShieldAlert } from "lucide-react"
import { api, ApiError, type VendorData, type VendorFields, type VendorReview } from "@/api"
import { useApi } from "@/useApi"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Failed, Loading, PageHeader } from "./common"

const ago = (ts: number) => {
  const s = Math.max(0, Date.now() / 1000 - ts)
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} days ago`
}

export function AnalyzerVendorPage() {
  const { data, error, reload } = useApi<VendorData>("/api/analyzer/vendor")
  const [review, setReview] = useState<VendorReview | null>(null)
  const [sent, setSent] = useState(false)

  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  const c = data.current
  const s = data.state

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <p className="mb-1 text-sm text-muted-foreground">
          <Link to="/analyzer" className="hover:underline">Analyzer</Link> / AI vendor{review && " / Confirm"}
        </p>
        <PageHeader title={review ? `Use ${review.label}?` : "AI vendor"}
          lead={review ? undefined : "Who the analyzer asks about each new message. Your lists and the built-in rules work the same whichever you choose."} />
      </div>

      {sent && <p role="status" className="text-sm text-success">Sent to the host. It's applied within 5 minutes, and your Discord channel (if set up) is told first.</p>}

      {review
        ? <Confirm review={review} currentLabel={c.label || c.provider}
            onCancel={() => setReview(null)} onDone={() => { setReview(null); setSent(true); reload() }} />
        : <>
            <p className="flex flex-wrap items-center gap-2 text-sm">
              Now: <span className="font-medium">{c.label || c.provider}</span>
              {c.model && <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{c.model}</code>}
              {s.pending
                ? <Badge variant="outline" className="gap-1"><Hourglass className="size-3" /> Change waiting for the host</Badge>
                : s.when ? <span className="text-muted-foreground">· last changed {ago(s.when)}</span> : null}
            </p>
            {data.no_price && (
              <Alert><Info /><AlertTitle>The analyzer isn't using this model yet</AlertTitle>
                <AlertDescription>It needs the model's prices to keep to your budget. Type them below.</AlertDescription></Alert>
            )}
            {s.result && s.result !== "ok" && !s.pending && (
              <Alert variant="destructive"><CircleAlert /><AlertTitle>The host didn't apply the last change</AlertTitle>
                <AlertDescription>{s.result}. Change it below and continue again.</AlertDescription></Alert>
            )}
            {!data.drop_writable && (
              <Alert variant="destructive"><CircleAlert /><AlertTitle>The portal can't send changes yet</AlertTitle>
                <AlertDescription>Run ./bridgekeep setup on the host to enable this.</AlertDescription></Alert>
            )}
            <Choose data={data} disabled={!data.drop_writable || s.pending} onReview={(r) => { setSent(false); setReview(r) }} />
          </>}
    </div>
  )
}

function Choose({ data, disabled, onReview }: { data: VendorData; disabled: boolean; onReview: (r: VendorReview) => void }) {
  const [f, setF] = useState<VendorFields>({ provider: data.current.provider, model: data.current.model, endpoint: "", price_in: "", price_out: "" })
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const v = data.vendors[f.provider]
  const set = (k: keyof VendorFields) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value })
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setErr(""); setBusy(true)
    api.post<VendorReview>("/api/analyzer/vendor/review", f).then(onReview, (x: ApiError) => setErr(x.message)).finally(() => setBusy(false))
  }

  return (
    <Card>
      <CardContent>
        <form onSubmit={submit} autoComplete="off" className="grid max-w-md gap-5">
          <div className="grid gap-2">
            <Label htmlFor="provider">Vendor</Label>
            <Select value={f.provider} onValueChange={(p) => setF({ ...f, provider: p, model: p === data.current.provider ? data.current.model : "" })}>
              <SelectTrigger id="provider" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {Object.entries(data.vendors).map(([id, x]) => <SelectItem key={id} value={id}>{x.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="model">Model name</Label>
            <Input id="model" maxLength={100} spellCheck={false} value={f.model} onChange={set("model")} />
            {v && <p className="text-xs text-muted-foreground">{v.model_hint}</p>}
          </div>
          {f.provider === "local" && (
            <div className="grid gap-2">
              <Label htmlFor="endpoint">Server address</Label>
              <Input id="endpoint" maxLength={300} spellCheck={false} placeholder="http://192.168.1.20:11434/v1" value={f.endpoint} onChange={set("endpoint")} />
              <p className="text-xs text-muted-foreground">An OpenAI-compatible address on your own network. A name is looked up once and its address is kept. It can't be Bridgekeep's own services.</p>
            </div>
          )}
          {(v?.needs_price || data.no_price) && (
            <fieldset className="grid gap-3">
              <legend className="mb-2 text-sm font-medium">Prices (US$ per million tokens)</legend>
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-2"><Label htmlFor="price_in">Input</Label>
                  <Input id="price_in" inputMode="decimal" maxLength={12} value={f.price_in} onChange={set("price_in")} /></div>
                <div className="grid gap-2"><Label htmlFor="price_out">Output</Label>
                  <Input id="price_out" inputMode="decimal" maxLength={12} value={f.price_out} onChange={set("price_out")} /></div>
              </div>
              <p className="text-xs text-muted-foreground">From the vendor's pricing page: prices change and differ by plan, and the analyzer only uses a model it can keep to your budget. To change only the prices, keep the same vendor and model.</p>
            </fieldset>
          )}
          {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
          <div className="space-y-2">
            <Button type="submit" disabled={disabled || busy}>Continue</Button>
            <p className="text-xs text-muted-foreground">Next you'll see who receives your mail and can type the API key. Continuing asks for your password if you haven't confirmed it in the last 5 minutes.</p>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}

function Confirm({ review: r, currentLabel, onCancel, onDone }: {
  review: VendorReview; currentLabel: string; onCancel: () => void; onDone: () => void
}) {
  const [key, setKey] = useState("")
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const f = r.fields
  const local = f.provider === "local"
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setErr(""); setBusy(true)
    api.post("/api/analyzer/vendor", { ...f, key }).then(
      () => { setKey(""); onDone() },
      (x: ApiError) => setErr(x.message)).finally(() => setBusy(false))
  }

  return (
    <div className="space-y-5">
      <Alert><ShieldAlert /><AlertTitle>Who receives your mail</AlertTitle><AlertDescription>{r.disclosure}</AlertDescription></Alert>
      {r.current_provider !== f.provider && <p className="text-sm">Mail fields will go to {r.label} instead of {currentLabel}.</p>}
      <Card className="gap-4">
        <CardHeader><CardTitle>{r.label}</CardTitle><CardDescription>What the host will switch to.</CardDescription></CardHeader>
        <CardContent className="space-y-5">
          <dl className="divide-y rounded-lg border text-sm">
            <Row label="Model"><code className="font-mono text-xs">{f.model}</code></Row>
            {f.endpoint && <Row label="Server"><code className="font-mono text-xs break-all">{f.endpoint}</code></Row>}
            {f.price_in && <Row label="Prices">${f.price_in} in, ${f.price_out} out, per million tokens</Row>}
          </dl>
          <form onSubmit={submit} autoComplete="off" className="grid max-w-md gap-4">
            <div className="grid gap-2">
              <Label htmlFor="vendor-key">API key for {r.label}</Label>
              <Input id="vendor-key" type="password" autoComplete="off" spellCheck={false} maxLength={220}
                placeholder={r.key_placeholder} value={key} onChange={(e) => setKey(e.target.value)} />
              <p className="text-xs text-muted-foreground">
                Leave it empty to keep the key already saved for {r.label}. If there isn't one{local && " and your server needs one"}, the host doesn't change anything and says why on this page.
                {local && " Most home servers don't need a key."} Make a key just for Bridgekeep, with a spend limit. The portal never shows it again.
              </p>
            </div>
            {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
            <p className="text-xs text-muted-foreground">The host applies this within 5 minutes and tells your Discord channel first. One change every 10 minutes.</p>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={busy}>Use {r.label}</Button>
              <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 px-4 py-2.5 sm:grid-cols-[7rem_1fr] sm:gap-3">
      <dt className="text-muted-foreground">{label}</dt><dd className="min-w-0">{children}</dd>
    </div>
  )
}
