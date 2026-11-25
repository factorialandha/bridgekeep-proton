import { useState } from "react"
import { Link } from "react-router"
import { Bell, ChevronRight, KeyRound, ShieldCheck, Wifi } from "lucide-react"
import { api, ApiError, type SettingsData } from "@/api"
import { useApi } from "@/useApi"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Failed, Loading, PageHeader, Section } from "./common"

function useForm<T extends Record<string, string>>(init: T) {
  const [v, setV] = useState(init)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const bind = (k: keyof T) => ({ value: v[k], onChange: (e: React.ChangeEvent<HTMLInputElement>) => setV({ ...v, [k]: e.target.value }) })
  const send = (path: string, ok: string, after?: () => void) => (e?: React.FormEvent) => {
    e?.preventDefault()
    setMsg(null)
    api.post(path, v).then(() => { setV(init); setMsg({ ok: true, text: ok }); after?.() },
      (x: ApiError) => setMsg({ ok: false, text: x.message }))
  }
  const note = msg && <p role={msg.ok ? "status" : "alert"} className={msg.ok ? "text-sm text-success" : "text-sm text-destructive"}>{msg.text}</p>
  return { bind, send, note }
}

export function SettingsPage() {
  const { data, error, reload } = useApi<SettingsData>("/api/settings")
  const pw = useForm({ password: "", confirm: "" })
  const on = useForm({ code: "" })
  const off = useForm({ password: "", code: "" })
  const hook = useForm({ name: "discord_webhook", value: "" })
  const [alertMsg, setAlertMsg] = useState("")
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  const a = data.alerts

  return (
    <div className="max-w-4xl">
      <PageHeader title="Settings" />

      <Section title="Access" description="Who can open this portal.">
        {data.lan ? (
          <>
            <div className="flex items-start gap-3 text-sm"><Wifi className="mt-0.5 size-4 text-muted-foreground" aria-hidden="true" />
              <div>Devices on your home network can open it at:
                <ul className="mt-1 space-y-0.5">{data.urls.map((u) => <li key={u}><code className="font-mono">{u}</code></li>)}</ul></div></div>
            <div className="text-sm">
              <p>It uses its own certificate, so each browser warns once. Continue only if the warning shows this SHA-256 fingerprint:</p>
              <pre className="mt-2 overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs leading-relaxed" aria-label="SHA-256 fingerprint">{data.fingerprint.join("\n")}</pre>
              <p className="mt-2 text-muted-foreground">To stop the warning, <a className="text-primary underline-offset-4 hover:underline" href="/portal.crt">download the certificate</a> and trust it on your device.</p>
            </div>
          </>
        ) : (
          <p className="text-sm">The portal listens on this host only, at <code className="font-mono">{data.urls[0]}</code>. Nothing on your network can reach it.</p>
        )}
        <p className="text-sm text-muted-foreground">Don't forward this port on your router. For access away from home, use a VPN such as Tailscale or WireGuard.</p>
      </Section>

      <Section title="Admin password" description={`At least ${data.min_password} characters.`}>
        <form onSubmit={pw.send("/api/settings/password", "Password changed. Other sessions were signed out.")} className="grid max-w-sm gap-3">
          <div className="grid gap-1.5"><Label htmlFor="pw">New password</Label>
            <Input id="pw" type="password" autoComplete="new-password" minLength={data.min_password} required {...pw.bind("password")} /></div>
          <div className="grid gap-1.5"><Label htmlFor="pw2">Type it again</Label>
            <Input id="pw2" type="password" autoComplete="new-password" minLength={data.min_password} required {...pw.bind("confirm")} /></div>
          {pw.note}
          <Button type="submit" className="w-fit">Change password</Button>
        </form>
      </Section>

      <Section title="Authenticator" description="A code from an app on your phone at every sign-in.">
        {data.totp_on ? (
          <>
            <p className="flex items-center gap-2 text-sm"><Badge variant="outline" className="text-success"><ShieldCheck /> On</Badge> Every sign-in needs a code from your authenticator app.</p>
            <Collapsible>
              <CollapsibleTrigger asChild><Button variant="ghost" size="sm" className="group -ml-2 text-muted-foreground"><ChevronRight className="transition-transform group-data-[state=open]:rotate-90" /> Turn it off</Button></CollapsibleTrigger>
              <CollapsibleContent>
                <form onSubmit={off.send("/api/settings/totp/off", "Authenticator off.", reload)} className="mt-3 grid max-w-sm gap-3">
                  <p className="text-sm text-muted-foreground">Sign-in will need only your password, which then must be at least 15 characters.</p>
                  <div className="grid gap-1.5"><Label htmlFor="off-pw">Password</Label><Input id="off-pw" type="password" autoComplete="current-password" required {...off.bind("password")} /></div>
                  <div className="grid gap-1.5"><Label htmlFor="off-code">Code from your authenticator</Label><Input id="off-code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} required className="font-mono" {...off.bind("code")} /></div>
                  {off.note}
                  <Button type="submit" variant="outline" className="w-fit">Turn off the authenticator</Button>
                </form>
              </CollapsibleContent>
            </Collapsible>
          </>
        ) : (
          <>
            <p className="flex items-center gap-2 text-sm"><Badge variant="outline" className="text-warning">Off</Badge> Anyone who learns your password can sign in.</p>
            <form onSubmit={on.send("/api/settings/totp/on", "Authenticator on. You'll enter a code at every sign-in.", reload)} className="grid gap-4 sm:grid-cols-[auto_1fr] sm:items-start">
              <img src="/api/settings/totp.svg" alt="QR code to scan with your authenticator app" width={176} height={176} className="rounded-lg border bg-white p-2" />
              <div className="grid max-w-sm gap-3">
                <p className="text-sm">Scan this with an authenticator app, then enter the code it shows.</p>
                {data.totp_secret && (
                  <Collapsible>
                    <CollapsibleTrigger asChild><Button type="button" variant="ghost" size="sm" className="group -ml-2 text-muted-foreground"><ChevronRight className="transition-transform group-data-[state=open]:rotate-90" /> Can't scan? Enter the key by hand</Button></CollapsibleTrigger>
                    <CollapsibleContent><code className="block rounded-md bg-muted px-3 py-2 font-mono text-sm break-all">{data.totp_secret}</code></CollapsibleContent>
                  </Collapsible>
                )}
                <div className="grid gap-1.5"><Label htmlFor="on-code">Code from the app</Label>
                  <Input id="on-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" maxLength={7} required className="font-mono tracking-widest" {...on.bind("code")} /></div>
                {on.note}
                <Button type="submit" className="w-fit">Turn on the authenticator</Button>
              </div>
            </form>
          </>
        )}
      </Section>

      <Section title="Alerts" description="A Discord channel hears when Bridge is signed out, an update is waiting, or the disk is nearly full.">
        <p className="flex flex-wrap items-center gap-2 text-sm">
          <Bell className="size-4 text-muted-foreground" aria-hidden="true" />
          {a.pending ? <><Badge variant="outline" className="text-warning">Waiting for the host</Badge> Applied within 5 minutes.</>
            : a.on ? <><Badge variant="outline" className="text-success">On</Badge> Webhook ending <code className="font-mono">…{a.last4}</code>{a.when_text && <span className="text-muted-foreground">· changed {a.when_text}</span>}</>
            : <><Badge variant="outline">Off</Badge></>}
        </p>
        {a.result && a.result !== "ok" && !a.pending && <p role="alert" className="text-sm text-destructive">The host didn't apply the last change: {a.result}</p>}
        <form onSubmit={hook.send("/api/secrets/set", "Sent to the host. The new channel gets a test message within 5 minutes.", reload)} className="grid max-w-md gap-3" autoComplete="off">
          <div className="grid gap-1.5">
            <Label htmlFor="hook">{a.on ? "New webhook URL" : "Webhook URL"}</Label>
            <Input id="hook" type="password" spellCheck={false} maxLength={220} placeholder="https://discord.com/api/webhooks/…" required {...hook.bind("value")} />
            <p className="text-xs text-muted-foreground">In Discord: Server Settings › Integrations › Webhooks › Copy Webhook URL. It's never shown again here.</p>
          </div>
          {hook.note}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={!data.alerts_writable || a.pending}>{a.on ? "Replace the webhook" : "Turn on alerts"}</Button>
            {a.on && <Button type="button" variant="outline" disabled={!data.alerts_writable || data.test_alert.pending}
              onClick={() => api.post("/api/alerts/test").then(() => setAlertMsg("Test message requested. It arrives within 5 minutes."), (x: ApiError) => setAlertMsg(x.message))}>Send a test message</Button>}
            {a.on && <Button type="button" variant="ghost" disabled={!data.alerts_writable || a.pending}
              onClick={() => api.post("/api/secrets/remove", { name: "discord_webhook" }).then(reload, (x: ApiError) => setAlertMsg(x.message))}>Turn off alerts</Button>}
          </div>
          {alertMsg && <p role="status" className="text-sm text-muted-foreground">{alertMsg}</p>}
        </form>
      </Section>

      <Section title="Audit log" description="Every sign-in and change made in the portal.">
        <Button asChild variant="outline" className="w-fit"><Link to="/audit"><KeyRound /> Open the audit log</Link></Button>
      </Section>
    </div>
  )
}
