import { CopyButton } from "@/components/copy-button"
import { cn } from "@/lib/utils"

/** Preformatted text, with a title bar and a copy button when it has a title. */
export function CodeBlock({
  title,
  code,
  wrap = false,
  className,
}: {
  title?: React.ReactNode
  code: string
  wrap?: boolean
  className?: string
}) {
  return (
    <div className={cn("min-w-0 overflow-hidden rounded-lg border", className)}>
      {title != null && (
        <div className="flex items-center justify-between gap-2 border-b bg-muted/50 py-1 pr-1 pl-3">
          <span className="truncate text-xs font-medium">{title}</span>
          <CopyButton text={code} variant="ghost" />
        </div>
      )}
      <pre
        className={cn(
          "overflow-x-auto p-3 font-mono text-xs leading-relaxed",
          wrap && "break-words whitespace-pre-wrap"
        )}
      >
        {code}
      </pre>
    </div>
  )
}
