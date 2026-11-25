import { useEffect, useRef, useState } from "react"
import { api, ApiError, onStepUp } from "./api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"

/** The "Confirm it's you" dialog for changes that need the password again. */
export function StepUp({ totp }: { totp: boolean }) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState("")
  const [code, setCode] = useState("")
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const settle = useRef<((ok: boolean) => void) | null>(null)

  useEffect(() => {
    onStepUp(() => new Promise<boolean>((resolve) => {
      settle.current = resolve
      setPassword(""); setCode(""); setErr(""); setOpen(true)
    }))
    return () => onStepUp(null)
  }, [])

  const close = (ok: boolean) => {
    setOpen(false); setPassword(""); setCode("")
    settle.current?.(ok); settle.current = null
  }
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    api.reauth(password, code).then(() => close(true), (x: ApiError) => setErr(x.message)).finally(() => setBusy(false))
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) close(false) }}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>Confirm it's you</DialogTitle>
            <DialogDescription>
              This change needs your password{totp ? " and a fresh code" : ""}. You won't be asked again for 5 minutes.
            </DialogDescription>
          </DialogHeader>
          <div className="my-4 grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="su-password">Password</Label>
              <Input id="su-password" type="password" autoComplete="current-password" required autoFocus
                value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            {totp && (
              <div className="grid gap-2">
                <Label htmlFor="su-code">Code from your authenticator</Label>
                <Input id="su-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" maxLength={7} required
                  className="font-mono tracking-widest" value={code} onChange={(e) => setCode(e.target.value)} />
              </div>
            )}
            {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => close(false)}>Cancel</Button>
            <Button type="submit" disabled={busy}>Confirm</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
