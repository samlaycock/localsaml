import { DiamondIcon, ExternalLinkIcon } from "lucide-react"
import { Link, matchPath, useLocation } from "react-router"

import { PresetDot } from "@/components/identity-editor"
import { ModeToggle } from "@/components/mode-toggle"
import { Badge } from "@/components/ui/badge"
import { buttonVariants } from "@/components/ui/button"
import { prefix } from "@/lib/page"
import { useInfo } from "@/lib/root"

/** Each nav entry, and the paths that show it as current. */
const NAV = [
  { to: "/", label: "Overview", paths: ["/"] },
  { to: "/dev", label: "Assertion generator", paths: ["/dev"] },
  { to: "/sp", label: "Test SP", paths: ["/sp"] },
  { to: "/dev/requests", label: "Requests", paths: ["/dev/requests"] },
]

export function AppHeader() {
  const info = useInfo()
  const { pathname } = useLocation()
  return (
    <header className="flex h-12 shrink-0 items-center gap-4 border-b px-4">
      <Link to="/" className="flex items-center gap-2 text-sm font-semibold">
        <span className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <DiamondIcon className="size-3.5" />
        </span>
        localsaml
        <Badge variant="secondary" className="font-mono font-normal">
          {info.version}
        </Badge>
      </Link>
      {info.preset && (
        <Badge variant="outline" className="font-normal">
          <PresetDot color={info.preset.color} />
          emulating {info.preset.name}
        </Badge>
      )}
      <nav className="flex items-center gap-1">
        {NAV.map(({ to, label, paths }) => {
          const current = paths.some((p) => matchPath(p, pathname))
          return (
            <Link
              key={to}
              to={to}
              aria-current={current ? "page" : undefined}
              className={buttonVariants({
                variant: current ? "secondary" : "ghost",
                size: "sm",
              })}
            >
              {label}
            </Link>
          )
        })}
        {[["Metadata", "/metadata"]].map(([label, path]) => (
          <a
            key={path}
            href={prefix + path}
            target="_blank"
            rel="noreferrer"
            className={buttonVariants({ variant: "ghost", size: "sm" })}
          >
            {label}
            <ExternalLinkIcon data-icon="inline-end" />
          </a>
        ))}
      </nav>
      <div className="ml-auto flex items-center gap-2">
        <ModeToggle />
      </div>
    </header>
  )
}
