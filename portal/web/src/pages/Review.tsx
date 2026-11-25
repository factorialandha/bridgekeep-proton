import { useState } from "react"
import { Link } from "react-router"
import { Check, ShieldCheck, Trash2 } from "lucide-react"
import { api, ApiError, type ReviewData } from "@/api"
import { useApi } from "@/useApi"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { Failed, Loading, PageHeader, Unavailable } from "./common"

export function ReviewPage() {
  const { data, error } = useApi<ReviewData>("/api/review")
  const [done, setDone] = useState<Record<number, "keep" | "trash">>({})
  const [fail, setFail] = useState<string>("")
  if (error) return <Failed error={error} />
  if (!data) return <Loading />
  const waiting = data.items.filter((i) => !done[i.id])

  const answer = (id: number, verdict: "keep" | "trash") => {
    setFail("")
    api.post("/api/review/verdict", { id, verdict }).then(
      () => setDone((d) => ({ ...d, [id]: verdict })),
      (e: ApiError) => setFail(e.message),
    )
  }

  return (
    <div className="max-w-3xl">
      <PageHeader title="Review" lead="Mail the analyzer wasn't sure about in the last 14 days. Your answer teaches it about the sender.">
        {waiting.length > 0 && <Badge variant="secondary">{waiting.length} waiting</Badge>}
      </PageHeader>
      {fail && <p role="alert" className="mb-3 text-sm text-destructive">{fail}</p>}
      {data.unavailable ? <Unavailable /> : data.items.length === 0 && <p className="text-muted-foreground">Nothing to review. The analyzer was sure about everything lately.</p>}
      <ul className="space-y-3">
        {data.items.map((r) => {
          const v = done[r.id]
          const pct = r.confidence != null ? Math.round(r.confidence * 100) : null
          const spam = r.label === "spam" || r.label === "phishing"
          return (
            <li key={r.id}>
              <Card className={v ? "gap-0 py-3 opacity-60" : "gap-0 py-4"}>
                <CardContent className="px-4 sm:px-5">
                  <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 text-sm">
                    <span className="min-w-0 truncate text-muted-foreground">{r.from_addr} · {r.when}</span>
                    {pct != null && (
                      <Badge variant="outline" className={spam ? "border-warning/40 text-warning" : "text-success"}>
                        {pct}% {spam ? "spam" : "not spam"}
                      </Badge>
                    )}
                  </div>
                  <Link to={`/log/entry?id=${r.id}`} className="mt-1 block font-semibold break-words hover:underline">
                    {r.subject === null ? "(subject not stored)" : r.subject || "(no subject)"}
                  </Link>
                  {!v && (
                    <>
                      <p className="mt-1 text-sm break-words text-muted-foreground">
                        {r.reason ? <>The AI says: “{r.reason}”</> : r.explain}
                      </p>
                      <div className="mt-3 flex flex-wrap items-center gap-2">
                        <Button variant="outline" size="sm" onClick={() => answer(r.id, "keep")}><Check /> Not spam</Button>
                        <Button variant="outline" size="sm" onClick={() => answer(r.id, "trash")}><Trash2 /> Spam</Button>
                        <Button asChild variant="link" size="sm" className="ml-auto px-0 text-muted-foreground">
                          <Link to={`/lists?add=protect&value=${encodeURIComponent(r.from_addr)}`}><ShieldCheck /> Never trash this sender</Link>
                        </Button>
                      </div>
                    </>
                  )}
                  {v && <p className="mt-1 text-sm text-muted-foreground">You said: {v === "keep" ? "not spam" : "spam"}. Thanks.</p>}
                </CardContent>
              </Card>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
