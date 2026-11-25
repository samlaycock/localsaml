import { RotateCwIcon, TriangleAlertIcon } from "lucide-react"
import * as React from "react"
import {
  isRouteErrorResponse,
  Outlet,
  useMatches,
  useRouteError,
} from "react-router"

import { AppHeader } from "@/components/app-header"
import { Banners } from "@/components/banners"
import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Toaster } from "@/components/ui/sonner"
import { Spinner } from "@/components/ui/spinner"

/** The page's title, from the deepest route that names one (protocol pages keep the server's). */
function useTitle() {
  const matches = useMatches()
  const title = [...matches]
    .reverse()
    .map((m) => (m.handle as { title?: string } | undefined)?.title)
    .find(Boolean)
  React.useEffect(() => {
    if (title) document.title = `${title} · localsaml`
  }, [title])
}

export function Root() {
  const { theme } = useTheme()
  useTitle()
  return (
    <div className="flex h-svh flex-col">
      <AppHeader />
      <Banners />
      <main className="min-h-0 flex-1 overflow-y-auto">
        <Outlet />
      </main>
      <Toaster theme={theme} />
    </div>
  )
}

/** Shown while the first page loads. */
export function Loading() {
  return (
    <div className="flex h-svh items-center justify-center">
      <Spinner className="size-6 text-muted-foreground" />
    </div>
  )
}

export function RouteError() {
  const error = useRouteError()
  const unreachable =
    error instanceof TypeError ||
    (error instanceof Error && error.message.includes("isn't responding"))
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : String(error)
  return (
    <Empty className="h-full">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <TriangleAlertIcon />
        </EmptyMedia>
        <EmptyTitle>
          {unreachable ? "localsaml isn't answering" : "Something went wrong"}
        </EmptyTitle>
        <EmptyDescription>
          {unreachable
            ? "Check that it's still running, then reload."
            : message}
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button variant="outline" onClick={() => location.reload()}>
          <RotateCwIcon data-icon="inline-start" />
          Reload
        </Button>
      </EmptyContent>
    </Empty>
  )
}
