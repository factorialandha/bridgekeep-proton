import { useEffect, useState } from "react"
import { NavLink, Outlet, useLocation } from "react-router"
import {
  Activity, Inbox, ScrollText, ListChecks, Sparkles, Settings, Ellipsis, Monitor, Moon, Sun, LogOut, Eye,
} from "lucide-react"
import { api, setCsrf, type Session } from "./api"
import { cn } from "@/lib/utils"
import icon from "@/assets/icon.svg"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { getTheme, setTheme, type Theme } from "./theme"
import { StepUp } from "./StepUp"

// Pages not yet moved to the new frontend are plain links to the server pages.
type Item = { to: string; label: string; icon: typeof Activity; spa: boolean; phone: boolean }
const NAV: Item[] = [
  { to: "/", label: "Status", icon: Activity, spa: true, phone: true },
  { to: "/review", label: "Review", icon: Inbox, spa: true, phone: true },
  { to: "/log", label: "Log", icon: ScrollText, spa: true, phone: true },
  { to: "/lists", label: "Lists", icon: ListChecks, spa: true, phone: true },
  { to: "/analyzer", label: "Analyzer", icon: Sparkles, spa: true, phone: false },
  { to: "/settings", label: "Settings", icon: Settings, spa: true, phone: false },
]

function Count({ n, className }: { n: number; className?: string }) {
  if (!n) return null
  return (
    <span className={cn("ml-auto rounded-full bg-warning px-1.5 text-[11px] leading-[18px] font-semibold text-background tabular-nums", className)}>
      <span aria-hidden="true">{n > 99 ? "99+" : n}</span>
      <span className="sr-only">, {n} waiting</span>
    </span>
  )
}

function NavItem({ item, waiting, phone }: { item: Item; waiting: number; phone?: boolean }) {
  const Icon = item.icon
  const inner = (active: boolean) => (
    <>
      <Icon className={phone ? "size-5" : "size-4"} aria-hidden="true" />
      <span>{item.label}</span>
      {item.label === "Review" && <Count n={waiting} className={phone ? "absolute top-0.5 left-[calc(50%+4px)] ml-0" : ""} />}
      {active && <span className="sr-only">(current page)</span>}
    </>
  )
  const cls = (active: boolean) => phone
    ? cn("relative flex flex-1 flex-col items-center gap-0.5 rounded-md py-1.5 text-[11px] font-medium min-h-12",
        active ? "text-primary" : "text-muted-foreground")
    : cn("flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors min-h-10",
        active ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground")
  if (!item.spa) return <a href={item.to} className={cls(false)}>{inner(false)}</a>
  return (
    <NavLink to={item.to} end={item.to === "/"} className={({ isActive }) => cls(isActive)}>
      {({ isActive }) => inner(isActive)}
    </NavLink>
  )
}

function ThemeMenu() {
  const [t, setT] = useState<Theme>(getTheme())
  const Icon = t === "light" ? Sun : t === "dark" ? Moon : Monitor
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Theme: ${t === "system" ? "Auto" : t}`}><Icon /></Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>Theme</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuRadioGroup value={t} onValueChange={(v) => { setT(v as Theme); setTheme(v as Theme) }}>
          <DropdownMenuRadioItem value="system"><Monitor /> Auto</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="light"><Sun /> Light</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark"><Moon /> Dark</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function Shell() {
  const [session, setSession] = useState<Session | null>(null)
  const loc = useLocation()
  useEffect(() => {
    api.get<Session>("/api/session").then((s) => {
      if (!s.signed_in) { window.location.href = "/login"; return }
      setCsrf(s.csrf)
      setSession(s)
    }, () => { window.location.href = "/login" })
  }, [loc.pathname])
  const waiting = session?.review_waiting ?? 0
  const moreActive = ["/more", "/analyzer", "/settings", "/audit", "/backfill", "/proton"].some((p) => loc.pathname.startsWith(p))

  return (
    <div className="min-h-svh bg-background">
      <StepUp totp={session?.totp_on ?? true} />
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded-md focus:bg-card focus:p-2">Skip to content</a>
      <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b bg-background/90 px-4 backdrop-blur">
        <a href="/app/" className="flex items-center gap-2 font-semibold">
          <img src={icon} alt="" width={24} height={24} />
          <span>{session?.product ?? "Bridgekeep"}</span>
        </a>
        {session?.mode === "shadow" && (
          <Badge variant="outline" className="hidden gap-1.5 sm:inline-flex">
            <Eye className="size-3.5" aria-hidden="true" /> Shadow mode: the analyzer only logs. Nothing is moved.
          </Badge>
        )}
        <div className="ml-auto flex items-center gap-1">
          <ThemeMenu />
          <form method="post" action="/logout">
            <input type="hidden" name="csrf" value={session?.csrf ?? ""} />
            <Button variant="ghost" size="sm" type="submit"><LogOut /> <span className="hidden sm:inline">Sign out</span></Button>
          </form>
        </div>
      </header>
      {session?.mode === "shadow" && (
        <p className="border-b bg-muted/60 px-4 py-1.5 text-xs text-muted-foreground sm:hidden">Shadow mode: the analyzer only logs. Nothing is moved.</p>
      )}
      <div className="flex">
        <nav aria-label="Main" className="sticky top-14 hidden h-[calc(100svh-3.5rem)] w-56 shrink-0 flex-col gap-1 border-r p-3 md:flex">
          {NAV.map((i) => <NavItem key={i.to} item={i} waiting={waiting} />)}
        </nav>
        <main id="main" className="min-w-0 flex-1 px-4 pt-6 pb-28 md:px-8 md:pb-10">
          <Outlet />
          {session && (
            <footer className="mt-12 border-t pt-4 text-xs text-muted-foreground">
              {[
                `Bridgekeep ${session.versions.bridgekeep || ""}${session.versions.commit ? ` (${session.versions.commit})` : ""}`.trim(),
                session.versions.portal && `Portal ${session.versions.portal}${session.versions.portal_commit ? ` (${session.versions.portal_commit})` : ""}`,
                session.versions.bridge && `Bridge ${session.versions.bridge}`,
              ].filter(Boolean).join(" · ")}
              {session.versions.portal_stale && (
                <p className="mt-1 text-amber-700 dark:text-amber-400">
                  This portal was built from older code than the checkout. Run ./bridgekeep setup on the server to update it.
                </p>
              )}
            </footer>
          )}
        </main>
      </div>
      <nav aria-label="Main" className="fixed inset-x-0 bottom-0 z-30 flex border-t bg-background/95 px-1 pb-[env(safe-area-inset-bottom)] backdrop-blur md:hidden">
        {NAV.filter((i) => i.phone).map((i) => <NavItem key={i.to} item={i} waiting={waiting} phone />)}
        <NavLink to="/more" className={cn("relative flex flex-1 flex-col items-center gap-0.5 rounded-md py-1.5 text-[11px] font-medium min-h-12",
          moreActive ? "text-primary" : "text-muted-foreground")}>
          <Ellipsis className="size-5" aria-hidden="true" /><span>More</span>
        </NavLink>
      </nav>
    </div>
  )
}
