import { useState } from "react"
import { Search, Undo2 } from "lucide-react"
import { Link, useSearchParams } from "react-router"
import type { LogData, LogRow } from "@/api"
import { useApi } from "@/useApi"
import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Failed, Loading, PageHeader, Unavailable } from "./common"

export function Result({ r }: { r: LogRow }) {
  if (r.moved_back) return <Badge variant="outline" className="text-success"><Undo2 /> Moved back</Badge>
  if (r.action === "quarantine")
    return <Badge variant="outline" className="border-destructive/40 text-destructive">{r.applied ? `Moved to ${r.moved_to ?? "AI-Quarantine"}` : "Would trash"}</Badge>
  if (r.action === "review")
    return <Badge variant="outline" className="border-warning/40 text-warning">{r.applied ? `Moved to ${r.moved_to ?? "AI-Review"}` : "Would review"}</Badge>
  return <Badge variant="outline" className="text-success">Kept</Badge>
}

function Verdict({ v }: { v: LogRow["verdict"] }) {
  if (!v) return null
  return <Badge variant="secondary" className="ml-1.5">You: {v === "keep" ? "not spam" : "spam"}</Badge>
}

const subjectOf = (r: LogRow) => (r.subject === null ? "(subject not stored)" : r.subject || "(no subject)")

export function LogPage() {
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState(params.get("q") ?? "")
  const { data, error } = useApi<LogData>(`/api/log?${params.toString()}`)
  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params)
    if (v) p.set(k, v); else p.delete(k)
    p.delete("before")
    setParams(p)
  }
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  if (data.unavailable || !data.card)
    return <div className="max-w-6xl"><PageHeader title="Log" lead="Everything the analyzer checked, newest first." /><Unavailable /></div>
  const c = data.card
  const filtered = params.get("q") || params.get("action") || params.get("flag") || (params.get("days") ?? "14") !== "14"

  return (
    <div className="max-w-6xl">
      <PageHeader title="Log" lead="Everything the analyzer checked, newest first." />
      <div className="mb-5 grid grid-cols-2 overflow-hidden rounded-xl border bg-card sm:grid-cols-5" role="group" aria-label="Last 14 days">
        {[["Checked", c.seen], ["Would trash", c.quarantine], ["Sent to Review", c.review], ["Protected saves", c.protected], ["Answered by you", c.answered]].map(([l, n], i) => (
          <div key={l} className={cn("border-border p-3 sm:border-r sm:last:border-r-0", i % 2 === 0 && "border-r", i < 2 && "border-b sm:border-b-0", i === 4 && "hidden sm:block")}>
            <p className="text-xs text-muted-foreground">{l}</p>
            <p className="text-xl font-semibold tabular-nums">{Number(n).toLocaleString()}</p>
          </div>
        ))}
      </div>

      <form role="search" className="mb-3 flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); set("q", q.trim()) }}>
        <div className="relative min-w-56 flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input aria-label="Search sender, domain or subject" placeholder="Search sender, domain or subject" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Select value={params.get("action") || "any"} onValueChange={(v) => set("action", v === "any" ? "" : v)}>
          <SelectTrigger aria-label="Result" className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any result</SelectItem>
            <SelectItem value="quarantine">Trash</SelectItem>
            <SelectItem value="review">Review</SelectItem>
            <SelectItem value="keep">Kept</SelectItem>
          </SelectContent>
        </Select>
        <Select value={params.get("days") || "14"} onValueChange={(v) => set("days", v === "14" ? "" : v)}>
          <SelectTrigger aria-label="Period" className="w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            {["1", "7", "14", "30", "90"].map((d) => <SelectItem key={d} value={d}>Last {d} day{d === "1" ? "" : "s"}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button type="submit" variant="secondary">Search</Button>
      </form>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {data.filters.map((f) => {
          const on = params.get("flag") === f.key
          return <Button key={f.key} size="sm" variant={on ? "default" : "outline"} className="rounded-full" aria-pressed={on} onClick={() => set("flag", on ? "" : f.key)}>{f.label}</Button>
        })}
        {filtered && <Button size="sm" variant="link" onClick={() => { setQ(""); setParams(new URLSearchParams()) }}>Clear</Button>}
      </div>

      {data.rows.length === 0 ? <p className="text-muted-foreground">Nothing matches.</p> : (
        <>
          {/* Desktop: a table; the whole row opens the entry. */}
          <Card className="hidden gap-0 py-0 md:block">
            <Table>
              <TableHeader>
                <TableRow><TableHead>Subject</TableHead><TableHead>Sender</TableHead><TableHead>Result</TableHead><TableHead>Why</TableHead><TableHead className="text-right">Time</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {data.rows.map((r) => (
                  <TableRow key={r.id} className="relative has-[a:focus-visible]:outline-2 has-[a:focus-visible]:outline-ring">
                    <TableCell className="max-w-80 whitespace-normal">
                      <Link to={`/log/entry?id=${r.id}`} className="font-medium outline-none after:absolute after:inset-0">{subjectOf(r)}</Link>
                      <Verdict v={r.verdict} />
                    </TableCell>
                    <TableCell className="max-w-56 truncate text-muted-foreground">{r.from_addr}</TableCell>
                    <TableCell><Result r={r} /></TableCell>
                    <TableCell className="max-w-72 whitespace-normal text-muted-foreground">{r.why}</TableCell>
                    <TableCell className="text-right text-muted-foreground tabular-nums"><time dateTime={new Date(r.ts * 1000).toISOString()} title={r.full_when}>{r.when}</time></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
          {/* Phone: compact rows. */}
          <Card className="gap-0 divide-y py-0 md:hidden">
            {data.rows.map((r) => (
              <Link key={r.id} to={`/log/entry?id=${r.id}`} className="block px-4 py-3 hover:bg-accent/50">
                <span className="flex items-start justify-between gap-3">
                  <span className="min-w-0 font-medium break-words">{subjectOf(r)}<Verdict v={r.verdict} /></span>
                  <Result r={r} />
                </span>
                <span className="mt-1 flex justify-between gap-3 text-sm text-muted-foreground">
                  <span className="min-w-0 truncate">{r.from_addr}</span><span className="shrink-0 tabular-nums">{r.when}</span>
                </span>
                <span className="mt-0.5 block text-sm text-muted-foreground">{r.why}</span>
              </Link>
            ))}
          </Card>
          {data.older && (
            <Button variant="outline" className="mt-4" onClick={() => set("before", data.older!)}>Older entries</Button>
          )}
        </>
      )}
    </div>
  )
}
