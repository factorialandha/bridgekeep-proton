import { useState } from "react"
import { ChevronRight, CircleAlert, Plus, RotateCcw, X } from "lucide-react"
import { useSearchParams } from "react-router"
import { api, ApiError, type ListsData } from "@/api"
import { useApi } from "@/useApi"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog"
import { Failed, Loading, PageHeader } from "./common"

type List = ListsData["lists"][number]
const KIND = { address: "Address", domain: "Whole domain", pattern: "Words" } as const

export function ListsPage() {
  const { data, error, reload } = useApi<ListsData>("/api/lists")
  const [params] = useSearchParams()
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  // "Never trash this sender" from Review and the Log: ?add=protect&value=<address>
  const pre = { list: (params.get("add") ?? "").split(":")[0], value: params.get("value") ?? "" }

  return (
    <div className="max-w-3xl space-y-5">
      <PageHeader title="Lists" lead="Rules the analyzer always follows, before it asks the AI. Changes apply within a minute." />
      {data.problems.length > 0 && (
        <Alert variant="destructive">
          <CircleAlert />
          <AlertTitle>The analyzer is ignoring {data.problems.length} {data.problems.length === 1 ? "entry" : "entries"}</AlertTitle>
          <AlertDescription>
            <ul className="mt-1 list-disc pl-4">{data.problems.map((p, i) => <li key={i}>{p.text}</li>)}</ul>
          </AlertDescription>
        </Alert>
      )}
      {data.lists.map((l) => (
        <ListCard key={l.key} list={l} writable={data.writable} onChange={reload}
          initial={pre.list === l.key && pre.value.length <= 254 ? pre.value : ""} />
      ))}
      {data.removed.length > 0 && (
        <Card className="gap-3">
          <CardHeader><CardTitle className="text-base">Removed</CardTitle>
            <CardDescription>These came with your setup. You removed them, so the analyzer ignores them.</CardDescription></CardHeader>
          <CardContent className="divide-y px-0">
            {data.removed.map((r) => (
              <div key={`${r.list}:${r.value}`} className="flex items-center justify-between gap-3 px-6 py-2">
                <span className="min-w-0 break-words">{r.value} <span className="text-sm text-muted-foreground">({r.label})</span></span>
                <Button variant="ghost" size="sm" disabled={!data.writable} aria-label={`Restore ${r.value} to ${r.label}`}
                  onClick={() => api.post("/api/lists/restore", { list: r.list, value: r.value }).then(reload)}><RotateCcw /> Restore</Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      <p className="text-sm text-muted-foreground">Adding or removing asks for your password if you haven't confirmed it in the last 5 minutes.</p>
    </div>
  )
}

function ListCard({ list, writable, onChange, initial }: { list: List; writable: boolean; onChange: () => void; initial: string }) {
  const [value, setValue] = useState(initial)
  const [reason, setReason] = useState("")
  const [until, setUntil] = useState("")
  const [subs, setSubs] = useState(false)
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const id = `l-${list.key}`

  const add = (e: React.FormEvent) => {
    e.preventDefault()
    setErr(""); setBusy(true)
    api.post("/api/lists/add", { list: list.key, value: value.trim(), reason: reason.trim(), expires: until, subdomains: subs }).then(
      () => { setValue(""); setReason(""); setUntil(""); setSubs(false); onChange() },
      (x: ApiError) => setErr(x.message),
    ).finally(() => setBusy(false))
  }

  return (
    <Card id={id} className="gap-4">
      <CardHeader>
        <CardTitle className="flex items-baseline gap-2">{list.label} <span className="text-sm font-normal text-muted-foreground tabular-nums">{list.entries.length}</span></CardTitle>
        <CardDescription>{list.help}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <form onSubmit={add} className="space-y-2">
          <div className="flex gap-2">
            <Label htmlFor={`${id}-v`} className="sr-only">{list.field} for {list.label}</Label>
            <Input id={`${id}-v`} placeholder={list.field} value={value} onChange={(e) => setValue(e.target.value)} maxLength={254}
              autoComplete="off" required autoFocus={Boolean(initial)} aria-invalid={Boolean(err)} aria-describedby={err ? `${id}-e` : undefined} />
            <Button type="submit" disabled={!writable || busy}><Plus /> Add</Button>
          </div>
          {err && <p id={`${id}-e`} role="alert" className="text-sm text-destructive">{err}</p>}
          <Collapsible>
            <CollapsibleTrigger asChild>
              <Button type="button" variant="ghost" size="sm" className="group -ml-2 text-muted-foreground">
                <ChevronRight className="transition-transform group-data-[state=open]:rotate-90" /> More options
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="grid gap-3 pt-2 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor={`${id}-r`}>Why <span className="font-normal text-muted-foreground">(optional)</span></Label>
                <Input id={`${id}-r`} maxLength={200} placeholder="e.g. Order and delivery updates" value={reason} onChange={(e) => setReason(e.target.value)} />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor={`${id}-u`}>Until <span className="font-normal text-muted-foreground">(optional)</span></Label>
                <Input id={`${id}-u`} type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
              </div>
              {list.key === "protect" && (
                <div className="flex items-start gap-2 sm:col-span-2">
                  <Checkbox id={`${id}-s`} checked={subs} onCheckedChange={(v) => setSubs(v === true)} />
                  <div className="grid gap-1">
                    <Label htmlFor={`${id}-s`}>Include subdomains (domains only)</Label>
                    <p className="text-xs text-muted-foreground">Free-mail domains such as gmail.com can only be added as exact addresses.</p>
                  </div>
                </div>
              )}
            </CollapsibleContent>
          </Collapsible>
        </form>
      </CardContent>
      {list.entries.length > 0 ? (
        <ul className="divide-y border-t">
          {list.entries.map((e) => (
            <li key={`${e.source}:${e.index}:${e.value}`} className="flex items-center justify-between gap-3 px-6 py-2.5">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-medium break-all">{e.kind === "pattern" ? `“${e.value}”` : `${e.subdomains ? "*." : ""}${e.value}`}</span>
                  <Badge variant="outline">{KIND[e.kind]}</Badge>
                  {e.source === "file" && <Badge variant="secondary">Came with setup</Badge>}
                </div>
                {(e.reason || e.expires) && (
                  <p className="mt-0.5 text-sm break-words text-muted-foreground">{e.reason}{e.expires && ` · until ${e.expires}`}</p>
                )}
              </div>
              <RemoveButton list={list} entry={e} writable={writable} onDone={onChange} />
            </li>
          ))}
        </ul>
      ) : <p className="border-t px-6 pt-3 text-sm text-muted-foreground">Nothing here yet.</p>}
    </Card>
  )
}

function RemoveButton({ list, entry, writable, onDone }: { list: List; entry: ListsData["lists"][number]["entries"][number]; writable: boolean; onDone: () => void }) {
  const [err, setErr] = useState("")
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" disabled={!writable} aria-label={`Remove ${entry.value} from ${list.label}`}><X /></Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="break-all">Remove {entry.value}?</DialogTitle>
          <DialogDescription>
            It comes off {list.label}. The analyzer stops using it within a minute.
            {entry.source === "file" && " It came with your setup; you can restore it from this page later."}
          </DialogDescription>
        </DialogHeader>
        {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
        <DialogFooter>
          <DialogClose asChild><Button variant="ghost">Cancel</Button></DialogClose>
          <Button variant="destructive" onClick={() => api.post("/api/lists/remove", { list: list.key, index: entry.index, value: entry.value, source: entry.source })
            .then(onDone, (x: ApiError) => setErr(x.message))}>Remove</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
