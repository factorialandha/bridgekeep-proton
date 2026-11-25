import { useEffect, useState } from "react"
import { CircleAlert, ExternalLink, Loader2, LogOut, Mail, PauseCircle, ShieldCheck } from "lucide-react"
import { api, ApiError, type ProtonStatus } from "@/api"
import { useApi } from "@/useApi"
import { safeHref } from "@/lib/utils"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Failed, Loading, PageHeader } from "./common"

/** Only an https link on proton.me (the server checks this too). */
function protonLink(url: string): string {
  const h = safeHref(url)
  try {
    const u = new URL(h)
    return u.protocol === "https:" && (u.hostname === "proton.me" || u.hostname.endsWith(".proton.me")) ? h : ""
  } catch {
    return ""
  }
}

function useCountdown(expires: number | null) {
  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    if (!expires) return
    const t = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(t)
  }, [expires])
  if (!expires) return ""
  const left = Math.max(0, Math.round(expires - now))
  return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`
}

export function ProtonPage() {
  const { data, error, reload } = useApi<ProtonStatus>("/api/proton")
  const [view, setView] = useState<ProtonStatus | null>(null)
  const [fail, setFail] = useState("")
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (data) setView(data) }, [data])
  const s = view
  // While Bridge works on it, check every 2 seconds.
  useEffect(() => {
    if (s?.state !== "signing_in") return
    const t = setInterval(reload, 2000)
    return () => clearInterval(t)
  }, [s?.state, reload])
  const left = useCountdown(s?.step_expires ?? null)

  if (error) return <Failed error={error} />
  if (!s) return <Loading />

  /** Every write answers with the new status, also on 409/429 (as `proton`). */
  const send = (path: string, body: object, after?: () => void) => {
    setFail(""); setBusy(true)
    return api.post<ProtonStatus>(path, body).then(
      (v) => { setView(v); after?.() },
      (e: ApiError) => {
        setFail(e.message)
        const p = e.data.proton as ProtonStatus | undefined
        if (p && typeof p === "object" && typeof p.state === "string") setView(p)
        else reload()
      }).finally(() => setBusy(false))
  }
  const cancel = <Button variant="ghost" disabled={busy} onClick={() => send("/api/proton/cancel", {})}>Cancel sign-in</Button>
  const waiting = s.state.startsWith("waiting")

  return (
    <div className="max-w-2xl space-y-5">
      <PageHeader title="Proton account" lead="The Proton account Bridge reads mail from. Signing in happens here; your Proton password goes to Bridge and is never stored by the portal." />

      {!s.available && (
        <Alert variant="destructive"><CircleAlert /><AlertTitle>The sign-in service isn't available</AlertTitle>
          <AlertDescription>{s.error || "Check the Status page."} Until it is, you can sign in on the host with ./bridgekeep relogin.</AlertDescription></Alert>
      )}
      {s.mail_paused && (
        <Alert><PauseCircle /><AlertTitle>Mail is paused while you sign in</AlertTitle>
          <AlertDescription>The analyzer picks up again once you're signed in.</AlertDescription></Alert>
      )}
      {fail && <p role="alert" className="text-sm text-destructive">{fail}</p>}
      {s.available && s.error && s.state !== "signed_out" && !fail && <p role="alert" className="text-sm text-destructive">{s.error}</p>}

      {s.available && s.state === "signed_in" && (
        <Card className="gap-4">
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2"><ShieldCheck className="size-5 text-success" aria-hidden="true" /> Signed in
              <Badge variant="outline" className="font-mono font-normal break-all">{s.account}</Badge></CardTitle>
            <CardDescription>Bridge is reading this account's mail.</CardDescription>
          </CardHeader>
          <CardContent><SignOut busy={busy} onConfirm={() => send("/api/proton/logout", { confirm: true })} /></CardContent>
        </Card>
      )}

      {s.available && (s.state === "signed_out" || s.state === "error") && (
        <SignIn busy={busy} error={s.state === "signed_out" ? s.error : ""}
          onSend={(username, password) => send("/api/proton/login", { username, password })} />
      )}

      {s.available && s.state === "signing_in" && (
        <Card className="gap-4">
          <CardHeader><CardTitle className="flex items-center gap-2"><Loader2 className="size-5 animate-spin" aria-hidden="true" /> Signing in…</CardTitle>
            <CardDescription>Bridge is talking to Proton. This page moves on by itself.</CardDescription></CardHeader>
          <CardContent>{cancel}</CardContent>
        </Card>
      )}

      {s.available && waiting && (
        <Card className="gap-4">
          <CardHeader>
            <CardTitle>{s.state === "waiting_2fa" ? "Two-factor code" : s.state === "waiting_mailbox_password" ? "Mailbox password" : "Proton wants to check you're human"}</CardTitle>
            <CardDescription>
              {s.account && <>Signing in as <span className="font-mono break-all">{s.account}</span>. </>}
              {left && <>This step closes in <span className="tabular-nums">{left}</span>.</>}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {s.state === "waiting_2fa" && <OneField key="2fa" id="code" label="Code from your authenticator app" busy={busy}
              inputMode="numeric" autoComplete="one-time-code" maxLength={10} button="Continue" after={cancel}
              onSend={(v) => send("/api/proton/2fa", { code: v })} />}
            {s.state === "waiting_mailbox_password" && <OneField key="mbx" id="mbx" label="Mailbox password" type="password" busy={busy}
              hint="Only accounts with two-password mode have one. It's not your sign-in password." maxLength={1024} button="Continue" after={cancel}
              onSend={(v) => send("/api/proton/mailbox-password", { password: v })} />}
            {s.state === "waiting_human" && <Human url={protonLink(s.hv_url)} busy={busy} after={cancel} onDone={() => send("/api/proton/human-verification", {})} />}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function SignIn({ busy, error, onSend }: { busy: boolean; error: string; onSend: (u: string, p: string) => Promise<void> }) {
  const [user, setUser] = useState("")
  const [pw, setPw] = useState("")
  useEffect(() => () => setPw(""), [])
  const submit = (e: React.FormEvent) => { e.preventDefault(); onSend(user.trim(), pw).finally(() => setPw("")) }
  return (
    <Card className="gap-4">
      <CardHeader><CardTitle className="flex items-center gap-2"><Mail className="size-5" aria-hidden="true" /> Sign in to Proton</CardTitle>
        <CardDescription>Use your Proton Mail address and password. Signing in asks for your portal password if you haven't confirmed it in the last 5 minutes.</CardDescription></CardHeader>
      <CardContent>
        <form onSubmit={submit} autoComplete="off" className="grid max-w-md gap-4">
          <div className="grid gap-2"><Label htmlFor="p-user">Proton address</Label>
            <Input id="p-user" type="email" autoComplete="username" spellCheck={false} maxLength={254} value={user} onChange={(e) => setUser(e.target.value)} required /></div>
          <div className="grid gap-2"><Label htmlFor="p-pw">Password</Label>
            <Input id="p-pw" type="password" autoComplete="current-password" maxLength={1024} value={pw} onChange={(e) => setPw(e.target.value)} required /></div>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <div><Button type="submit" disabled={busy}>Sign in</Button></div>
        </form>
      </CardContent>
    </Card>
  )
}

function OneField({ id, label, hint, button, busy, onSend, after, ...input }: {
  id: string; label: string; hint?: string; button: string; busy: boolean; onSend: (v: string) => Promise<void>; after: React.ReactNode
} & React.ComponentProps<typeof Input>) {
  const [v, setV] = useState("")
  const submit = (e: React.FormEvent) => { e.preventDefault(); onSend(v.trim()).finally(() => setV("")) }
  return (
    <form onSubmit={submit} autoComplete="off" className="grid max-w-xs gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} {...input} value={v} onChange={(e) => setV(e.target.value)} required autoFocus />
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      <div className="flex flex-wrap gap-2 pt-2"><Button type="submit" disabled={busy}>{button}</Button>{after}</div>
    </form>
  )
}

function Human({ url, busy, onDone, after }: { url: string; busy: boolean; onDone: () => void; after: React.ReactNode }) {
  return (
    <div className="space-y-3 text-sm">
      <p>Open Proton's check in a new tab, complete it, then come back and press "I've done it".</p>
      <div className="flex flex-wrap gap-2">
        {url
          ? <Button asChild variant="outline"><a href={url} target="_blank" rel="noopener noreferrer"><ExternalLink /> Open Proton's check</a></Button>
          : <p className="text-destructive">Proton didn't give a usable link. Cancel and sign in again.</p>}
        <Button onClick={onDone} disabled={busy}>I've done it</Button>
        {after}
      </div>
    </div>
  )
}

function SignOut({ busy, onConfirm }: { busy: boolean; onConfirm: () => Promise<void> }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button variant="outline"><LogOut /> Sign out of Proton</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Sign out of Proton?</DialogTitle>
          <DialogDescription>Bridge stops reading mail and the analyzer has nothing new to check until you sign in again here. Nothing in your mailbox changes.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="destructive" disabled={busy} onClick={() => onConfirm().then(() => setOpen(false))}>Sign out</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
