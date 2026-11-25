import { Link } from "react-router"
import type { AuditData } from "@/api"
import { useApi } from "@/useApi"
import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Failed, Loading, PageHeader } from "./common"

export function AuditPage() {
  const { data, error } = useApi<AuditData>("/api/audit")
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  return (
    <div className="max-w-5xl">
      <p className="mb-1 text-sm text-muted-foreground"><Link to="/settings" className="hover:underline">Settings</Link> / Audit log</p>
      <PageHeader title="Audit log" lead="Newest first. Secrets are never recorded." />
      <Card className="gap-0 py-0">
        <Table>
          <TableHeader><TableRow><TableHead>Time</TableHead><TableHead>Action</TableHead><TableHead className="hidden sm:table-cell">Target</TableHead><TableHead className="hidden md:table-cell">From</TableHead><TableHead>Result</TableHead></TableRow></TableHeader>
          <TableBody>
            {data.rows.length === 0 && <TableRow><TableCell colSpan={5} className="text-muted-foreground">Nothing yet.</TableCell></TableRow>}
            {data.rows.map((r) => (
              <TableRow key={r.id}>
                <TableCell className="text-muted-foreground tabular-nums">{r.when}</TableCell>
                <TableCell className="whitespace-normal">{r.action}<span className="block font-mono text-xs break-all text-muted-foreground sm:hidden">{r.target}</span></TableCell>
                <TableCell className="hidden max-w-72 font-mono text-xs break-all whitespace-normal sm:table-cell">{r.target}</TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">{r.ip}</TableCell>
                <TableCell>{r.result === "ok" ? <Badge variant="outline" className="text-success">ok</Badge> : <Badge variant="outline" className="border-destructive/40 text-destructive">{r.result}</Badge>}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  )
}
