import { AlertCircle, Info } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"
import type { ApiError } from "@/api"

export function PageHeader({ title, children, lead }: { title: string; children?: React.ReactNode; lead?: string }) {
  return (
    <div className="mb-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {children}
      </div>
      {lead && <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{lead}</p>}
    </div>
  )
}

export function Loading() {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-24 w-full max-w-3xl" />
      <Skeleton className="h-24 w-full max-w-3xl" />
    </div>
  )
}

export function Failed({ error }: { error: ApiError }) {
  return (
    <Alert variant="destructive" className="max-w-3xl">
      <AlertCircle />
      <AlertTitle>This page couldn't load</AlertTitle>
      <AlertDescription>{error.message}</AlertDescription>
    </Alert>
  )
}

export function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="grid gap-4 border-t py-6 first:border-t-0 first:pt-0 md:grid-cols-[14rem_1fr] md:gap-8">
      <div>
        <h2 className="text-base font-semibold">{title}</h2>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      <div className="min-w-0 space-y-5">{children}</div>
    </section>
  )
}

/** The analyzer hasn't written its database yet (first start) or it can't be read. */
export function Unavailable() {
  return (
    <Alert className="max-w-3xl">
      <Info />
      <AlertTitle>No analyzer results yet</AlertTitle>
      <AlertDescription>The analyzer hasn't recorded anything the portal can read. If it has only just started, this fills in after it checks the first new mail. The Status page shows whether it's running.</AlertDescription>
    </Alert>
  )
}
