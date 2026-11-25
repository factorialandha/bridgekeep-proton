import { ChevronRight, History, Mail, ScrollText, Settings, Sparkles } from "lucide-react"
import { Link } from "react-router"
import { Card } from "@/components/ui/card"
import { PageHeader } from "./common"

const ITEMS = [
  { to: "/proton", spa: true, icon: Mail, label: "Proton account", sub: "Sign Bridge in to Proton, or sign it out" },
  { to: "/analyzer", spa: true, icon: Sparkles, label: "Analyzer", sub: "AI vendor, budget, how strict it is" },
  { to: "/backfill", spa: true, icon: History, label: "Older mail", sub: "Analyze mail from before setup, after a cost estimate" },
  { to: "/settings", spa: true, icon: Settings, label: "Settings", sub: "Password, authenticator, alerts, network access" },
  { to: "/audit", spa: true, icon: ScrollText, label: "Audit log", sub: "Every change made in the portal" },
]

export function MorePage() {
  return (
    <div className="max-w-2xl">
      <PageHeader title="More" />
      <Card className="gap-0 divide-y py-0">
        {ITEMS.map(({ to, spa, icon: Icon, label, sub }) => {
          const body = (
            <>
              <Icon className="size-5 text-muted-foreground" aria-hidden="true" />
              <span className="min-w-0 flex-1"><span className="block font-medium">{label}</span><span className="block text-sm text-muted-foreground">{sub}</span></span>
              <ChevronRight className="size-4 text-muted-foreground" aria-hidden="true" />
            </>
          )
          const cls = "flex min-h-14 items-center gap-3 px-4 py-3 hover:bg-accent/50"
          return spa ? <Link key={to} to={to} className={cls}>{body}</Link> : <a key={to} href={to} className={cls}>{body}</a>
        })}
      </Card>
    </div>
  )
}
