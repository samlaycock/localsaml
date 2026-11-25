import { CheckIcon, CopyIcon } from "lucide-react"
import * as React from "react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"

export function CopyButton({
  text,
  label = "Copy",
  variant = "outline",
  size = "xs",
  ...props
}: { text: string; label?: string } & Omit<
  React.ComponentProps<typeof Button>,
  "onClick" | "children"
>) {
  const [copied, setCopied] = React.useState(false)

  React.useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), 1200)
    return () => clearTimeout(timer)
  }, [copied])

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
    } catch {
      // The clipboard needs a secure context: localhost, or HTTPS.
      toast.error("Couldn't copy to the clipboard")
    }
  }

  return (
    <Button variant={variant} size={size} onClick={copy} {...props}>
      {copied ? (
        <CheckIcon data-icon="inline-start" />
      ) : (
        <CopyIcon data-icon="inline-start" />
      )}
      {copied ? "Copied" : label}
    </Button>
  )
}
