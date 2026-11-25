import { ChevronDownIcon, ExternalLinkIcon } from "lucide-react"
import * as React from "react"

import { CodeBlock } from "@/components/code-block"
import { CopyButton } from "@/components/copy-button"
import { XmlBlock } from "@/components/xml-block"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { short } from "@/lib/identity"
import { prefix } from "@/lib/page"
import type { Minted } from "@/lib/types"

export type MintOutcome =
  | { ok: true; minted: Minted; request: Record<string, unknown> }
  | { ok: false; message: string; data: unknown }

/** Posts the Response to its ACS in a new tab, as a browser would after a login. */
function postToAcs(minted: Minted) {
  const form = document.createElement("form")
  form.method = "post"
  form.action = minted.acs_url
  form.target = "_blank"
  const fields: [string, string | null | undefined][] = [
    ["SAMLResponse", minted.saml_response],
    ["RelayState", minted.relay_state],
  ]
  for (const [name, value] of fields) {
    if (!value) continue
    const input = document.createElement("input")
    input.type = "hidden"
    input.name = name
    input.value = value
    form.append(input)
  }
  document.body.append(form)
  form.submit()
  form.remove()
}

/** The Response just minted, and how to use it. */
export function MintResult({ result }: { result: MintOutcome }) {
  const ref = React.useRef<HTMLDivElement>(null)
  React.useEffect(() => {
    ref.current?.scrollIntoView({ behavior: "smooth", block: "start" })
  }, [result])

  if (!result.ok) {
    return (
      <div ref={ref} className="scroll-mt-6">
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{result.message}</AlertDescription>
        </Alert>
      </div>
    )
  }
  const { minted: m, request } = result
  const tampers = Array.isArray(request.tamper)
    ? (request.tamper as string[])
    : []
  const api = `curl -s -X POST ${location.origin}${prefix}/dev/api/response -H 'content-type: application/json' -d '${JSON.stringify(request).replace(/'/g, "'\\''")}'`
  const chip = (on: boolean, yes: string, no: string) => (
    <Badge
      variant={on ? "secondary" : "outline"}
      className={on ? undefined : "text-muted-foreground"}
    >
      {on ? yes : no}
    </Badge>
  )
  return (
    <Card ref={ref} className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Result</CardDescription>
        <CardTitle>
          Response for <span className="font-mono text-primary">{m.sp}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <div className="flex flex-wrap gap-1.5">
          {chip(m.signed.response, "response signed", "response unsigned")}
          {chip(m.signed.assertion, "assertion signed", "assertion unsigned")}
          {m.encrypted && chip(true, "encrypted", "")}
          {m.name_id_encrypted && chip(true, "NameID encrypted", "")}
          {m.attributes_encrypted && chip(true, "attributes encrypted", "")}
          {tampers.map((t) => (
            <Badge key={t} variant="destructive">
              {t}
            </Badge>
          ))}
        </div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">ACS URL</dt>
          <dd className="font-mono text-xs break-all">{m.acs_url}</dd>
          <dt className="text-muted-foreground">NameID</dt>
          <dd className="font-mono text-xs break-all">
            {m.name_id}{" "}
            <span className="font-sans text-muted-foreground">
              {short(m.name_id_format)}
            </span>
          </dd>
        </dl>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => postToAcs(m)}>
            <ExternalLinkIcon data-icon="inline-start" />
            POST to the ACS (new tab)
          </Button>
          <CopyButton
            text={m.saml_response}
            label="Copy SAMLResponse"
            size="default"
          />
        </div>
        <XmlBlock title="SAML Response" xml={m.pretty} />
        <section className="flex flex-col gap-3">
          <h3 className="text-sm font-medium">Use it</h3>
          <CodeBlock title="Post it with curl" code={m.curl} wrap />
          <CodeBlock title="Reproduce via the API" code={api} wrap />
          <Collapsible>
            <CollapsibleTrigger
              render={
                <Button variant="ghost" size="sm" className="group -ml-2.5" />
              }
            >
              Raw API response
              <ChevronDownIcon
                data-icon="inline-end"
                className="transition-transform group-data-panel-open:rotate-180"
              />
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-2">
              <pre className="max-h-96 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">
                {JSON.stringify({ ...m, xml: "…", pretty: "…" }, null, 2)}
              </pre>
            </CollapsibleContent>
          </Collapsible>
        </section>
      </CardContent>
    </Card>
  )
}
