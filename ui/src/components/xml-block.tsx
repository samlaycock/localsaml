import { CopyButton } from "@/components/copy-button"
import { cn } from "@/lib/utils"

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")

/**
 * Indented XML as highlighted HTML, in theme colours: element names take the accent, attribute
 * names and comments are muted.
 */
export function highlightXml(xml: string) {
  return xml.replace(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g, (tok) => {
    if (tok.startsWith("<!--")) {
      return `<span class="text-muted-foreground italic">${escapeHtml(tok)}</span>`
    }
    if (tok.startsWith("<")) {
      // Attributes first: the element name's markup would match the attribute pattern.
      return escapeHtml(tok)
        .replace(
          /([\w:.-]+)=("[^"]*")/g,
          '<span class="text-muted-foreground">$1</span>=<span class="text-foreground">$2</span>'
        )
        .replace(
          /^(&lt;\/?)([\w:.-]+)/,
          '$1<span class="text-primary">$2</span>'
        )
    }
    return tok.trim()
      ? `<span class="font-medium text-foreground">${escapeHtml(tok)}</span>`
      : escapeHtml(tok)
  })
}

/** XML, highlighted, with a title and a copy button. */
export function XmlBlock({
  title,
  xml,
  className,
}: {
  title: React.ReactNode
  xml: string
  className?: string
}) {
  return (
    <div className={cn("min-w-0 overflow-hidden rounded-lg border", className)}>
      <div className="flex items-center justify-between gap-2 border-b bg-muted/50 py-1 pr-1 pl-3">
        <span className="truncate text-xs font-medium">{title}</span>
        <CopyButton text={xml} variant="ghost" />
      </div>
      <pre
        className="max-h-[32rem] overflow-auto p-3 font-mono text-xs leading-relaxed text-muted-foreground"
        dangerouslySetInnerHTML={{ __html: highlightXml(xml) }}
      />
    </div>
  )
}
