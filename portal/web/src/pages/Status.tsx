import { CheckCircle2, CircleAlert, ChevronRight, TriangleAlert } from "lucide-react"
import { Link } from "react-router"
import { api, type StatusData } from "@/api"
import { useApi } from "@/useApi"
import { cn, safeHref } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Table, TableBody, TableCell, TableHead, TableRow } from "@/components/ui/table"
import { Failed, Loading, PageHeader } from "./common"

const TONE = { ok: "text-success", warn: "text-warning", bad: "text-destructive", muted: "text-muted-foreground" } as const

export function StatusPage() {
  const { data, error, reload } = useApi<StatusData>("/api/status")
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  const g = data.glance
  const spendPct = g.spend != null && g.budget ? Math.min(100, (g.spend / g.budget) * 100) : null

  return (
    <div className="max-w-4xl">
      <PageHeader title="Status" />
      <Card className={cn("mb-4 gap-3 border-l-4 py-4", data.summary.ok ? "border-l-success" : "border-l-destructive")} role="status">
        <CardContent className="px-5">
          <p className="flex items-center gap-2 text-lg font-semibold">
            {data.summary.ok
              ? <CheckCircle2 className="size-5 text-success" aria-hidden="true" />
              : <CircleAlert className="size-5 text-destructive" aria-hidden="true" />}
            {data.summary.headline}
          </p>
          {data.needs.length > 0 && (
            <ul className="mt-3 divide-y rounded-md border">
              {data.needs.map((n, i) => (
                <li key={i} className="flex min-h-11 flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                  {n.level === "bad"
                    ? <CircleAlert className="size-4 shrink-0 text-destructive" aria-hidden="true" />
                    : <TriangleAlert className="size-4 shrink-0 text-warning" aria-hidden="true" />}
                  <span className="font-medium">{n.text}</span>
                  {n.how && <span className="text-muted-foreground">{n.how}</span>}
                  {n.href && (
                    <Button asChild variant="outline" size="sm" className="ml-auto">
                      {n.href.startsWith("/app/")
                        ? <Link to={n.href.slice(4)}>{linkLabel(n.action)} <ChevronRight /></Link>
                        : <a href={safeHref(n.href)}>{linkLabel(n.action)} <ChevronRight /></a>}
                    </Button>
                  )}
                  {n.action === "resume" && (
                    <Button size="sm" className="ml-auto" onClick={() => api.post("/api/analyzer/resume").then(reload)}>Resume</Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <div className="mb-6 grid grid-cols-2 overflow-hidden rounded-xl border bg-card md:grid-cols-4 [&>*]:border-border [&>*:nth-child(odd)]:border-r md:[&>*]:border-r md:[&>*:last-child]:border-r-0 [&>*:nth-child(-n+2)]:border-b md:[&>*:nth-child(-n+2)]:border-b-0">
        <Glance label="Bridge" value={g.bridge} tone={g.bridge_ok ? "ok" : "bad"} />
        <Glance label="Mail synced" value={g.messages != null ? g.messages.toLocaleString() : "—"} />
        <Glance label="AI this month" value={g.spend != null ? `$${g.spend.toFixed(2)}` : "—"} sub={g.budget ? `of $${g.budget}` : undefined}>
          {spendPct != null && <Progress value={spendPct} className="mt-2 h-1.5" aria-label="AI spend against budget" />}
        </Glance>
        <Glance label="Disk free" value={g.disk_free ?? "—"} sub={g.disk_used_pct != null ? `${g.disk_used_pct}% used` : undefined} />
      </div>

      <Collapsible>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" className="group -ml-3 text-muted-foreground">
            <ChevronRight className="transition-transform group-data-[state=open]:rotate-90" /> Details
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="mt-2 space-y-6">
          {data.details.map((sec) => (
            <section key={sec.label}>
              <h2 className="mb-2 text-sm font-semibold text-muted-foreground">{sec.label}</h2>
              <Card className="gap-0 py-0">
                <Table>
                  <TableBody>
                    {sec.rows.map((r) => (
                      <TableRow key={r.label}>
                        <TableHead scope="row" className="h-auto w-40 py-2.5 align-top whitespace-normal">{r.label}</TableHead>
                        <TableCell className={cn("py-2.5 align-top whitespace-normal", r.tone && TONE[r.tone])}>{r.value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Card>
            </section>
          ))}
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}

function Glance({ label, value, sub, tone, children }: {
  label: string; value: string; sub?: string; tone?: "ok" | "bad"; children?: React.ReactNode
}) {
  return (
    <div className="p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 flex flex-wrap items-baseline gap-x-1.5 text-xl font-semibold tabular-nums">
        {tone && <span className={cn("size-2 shrink-0 self-center rounded-full", tone === "ok" ? "bg-success" : "bg-destructive")} aria-hidden="true" />}
        {value}
        {sub && <span className="text-sm font-normal text-muted-foreground">{sub}</span>}
      </p>
      {children}
    </div>
  )
}

/** A need's link reads as its action ("Sign in"), or "Open". "resume" is a button, not a label. */
function linkLabel(action?: string) {
  return action && action !== "resume" && action.length <= 24 ? action : "Open"
}
