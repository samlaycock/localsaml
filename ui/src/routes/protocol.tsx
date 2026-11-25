import {
  CheckIcon,
  ChevronDownIcon,
  DotIcon,
  LogInIcon,
  SendIcon,
  XIcon,
} from "lucide-react"
import * as React from "react"
import { flushSync } from "react-dom"
import { useLocation } from "react-router"

import { IdentityEditor, SaveIdentity } from "@/components/identity-editor"
import { XmlBlock } from "@/components/xml-block"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { Field, FieldLabel } from "@/components/ui/field"
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  build,
  initialEditor,
  loadIdentity,
  rememberLast,
  short,
  storedEntry,
} from "@/lib/identity"
import { initialPath, page } from "@/lib/page"
import type { Entry, ProtocolView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { NotFound } from "@/routes/not-found"

type View<K extends ProtocolView["kind"]> = Extract<ProtocolView, { kind: K }>

/**
 * The protocol's pages: the server decides which (sign-in, review, sign-out, the test SP's
 * verdict, an error) and sends what it needs. Leaving the page and coming back shows it again;
 * any other address the app doesn't know is not found.
 */
export function ProtocolPage() {
  const { pathname } = useLocation()
  const view = page.view
  if (!view || pathname !== stripPrefix(initialPath)) return <NotFound />
  switch (view.kind) {
    case "login":
      return <LoginView view={view} />
    case "review":
      return <ReviewView view={view} />
    case "pick-sp":
      return <PickSpView view={view} />
    case "signed-out":
      return <SignedOutView view={view} />
    case "sp-outcome":
      return <SpOutcomeView view={view} />
    case "message":
      return (
        <MessageView
          eyebrow="localsaml"
          title={view.title}
          detail={view.detail}
        />
      )
    case "error":
      return (
        <MessageView
          eyebrow={view.label}
          title={view.title}
          detail={view.detail}
          error
        />
      )
  }
}

const stripPrefix = (path: string) =>
  page.prefix && path.startsWith(page.prefix)
    ? path.slice(page.prefix.length) || "/"
    : path

function Narrow({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 p-6 pt-16">
      {children}
    </div>
  )
}

function MessageView({
  eyebrow,
  title,
  detail,
  error = false,
}: {
  eyebrow: string
  title: string
  detail: string
  error?: boolean
}) {
  return (
    <Narrow>
      <Card>
        <CardHeader>
          <CardDescription className={error ? "text-destructive" : undefined}>
            {eyebrow}
          </CardDescription>
          <CardTitle className="text-xl">{title}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{detail}</p>
        </CardContent>
      </Card>
    </Narrow>
  )
}

function Disclosure({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <Collapsible>
      <CollapsibleTrigger
        render={<Button variant="ghost" size="sm" className="group -ml-2.5" />}
      >
        {label}
        <ChevronDownIcon
          data-icon="inline-end"
          className="transition-transform group-data-panel-open:rotate-180"
        />
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-3">{children}</CollapsibleContent>
    </Collapsible>
  )
}

const REVIEW_KEY = "localsaml.review"

/** The previous UI's "review before sending" preference: "1" or "0". */
function reviewPreference() {
  try {
    return localStorage.getItem(REVIEW_KEY) === "1"
  } catch {
    return false
  }
}

function LoginView({ view }: { view: View<"login"> }) {
  const data = view.editor
  const [state, setState] = React.useState(() => initialEditor(data))
  const [review, setReview] = React.useState(reviewPreference)
  const form = React.useRef<HTMLFormElement>(null)
  const approve = React.useRef<HTMLButtonElement>(null)
  const { identity, errors } = build(data.presets, state)

  /** Sign in as one of the quick identities. */
  function use(entry: Entry) {
    flushSync(() =>
      setState((s) => loadIdentity(s, data, entry.preset, entry.identity))
    )
    form.current?.requestSubmit(approve.current)
  }

  return (
    <div className="mx-auto grid max-w-6xl items-start gap-6 p-6 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <CardDescription>Authentication request</CardDescription>
          <CardTitle className="text-xl break-words">
            Sign in to <span className="text-primary">{view.sp}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-1">
            {view.chips.map((c) => (
              <Badge
                key={c.label}
                variant={
                  c.tone === "ok"
                    ? "default"
                    : c.tone === "warn"
                      ? "destructive"
                      : "secondary"
                }
              >
                {c.label}
              </Badge>
            ))}
          </div>
          {view.warnings.map((w) => (
            <Alert key={w}>
              <AlertDescription>{w}</AlertDescription>
            </Alert>
          ))}
          <Disclosure label="Request details">
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
              {view.details.map((d) => (
                <div key={d.label} className="contents">
                  <dt className="text-muted-foreground">{d.label}</dt>
                  <dd
                    className={cn(
                      "min-w-0 break-words",
                      d.code && "font-mono text-xs"
                    )}
                  >
                    {d.value}
                  </dd>
                </div>
              ))}
            </dl>
          </Disclosure>
          {view.requestXml && (
            <Disclosure label="AuthnRequest XML">
              <XmlBlock title="AuthnRequest" xml={view.requestXml} />
            </Disclosure>
          )}
        </CardContent>
      </Card>
      <form
        ref={form}
        method="post"
        action={view.action}
        id="lo-form"
        onSubmit={(e) => {
          const submitter = (e.nativeEvent as SubmitEvent)
            .submitter as HTMLButtonElement | null
          if (submitter?.value === "deny") return
          if (errors.length) {
            e.preventDefault()
            return
          }
          rememberLast(storedEntry(state, identity))
        }}
      >
        <Card>
          <input type="hidden" name="req" value={view.req} />
          <input type="hidden" name="preset" value={state.preset} />
          <input
            type="hidden"
            name="identity"
            value={JSON.stringify(identity)}
          />
          <CardContent>
            <IdentityEditor
              data={data}
              state={state}
              setState={setState}
              onUse={use}
            />
          </CardContent>
          <CardFooter className="flex flex-wrap items-center justify-between gap-3 border-t">
            <div className="flex flex-wrap items-center gap-3">
              <Button ref={approve} type="submit" name="action" value="approve">
                <LogInIcon data-icon="inline-start" />
                Sign in
              </Button>
              <Button
                type="submit"
                name="action"
                value="deny"
                variant="outline"
              >
                Deny
              </Button>
              <Field orientation="horizontal" className="w-fit">
                <Checkbox
                  id="lo-review"
                  name="review"
                  value="1"
                  checked={review}
                  onCheckedChange={(on) => {
                    setReview(on)
                    try {
                      localStorage.setItem(REVIEW_KEY, on ? "1" : "0")
                    } catch {
                      // Not kept.
                    }
                  }}
                />
                <FieldLabel htmlFor="lo-review" className="font-normal">
                  Review the response before sending it
                </FieldLabel>
              </Field>
            </div>
            <SaveIdentity data={data} state={state} />
          </CardFooter>
        </Card>
      </form>
    </div>
  )
}

function ReviewView({ view }: { view: View<"review"> }) {
  const send = view.send
  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription>Review</CardDescription>
          <CardTitle className="text-xl">
            Response for <span className="text-primary">{view.sp}</span>
          </CardTitle>
          <CardDescription>
            This is what will be {view.how} <code>{view.acs}</code>. Nothing has
            been sent yet.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {send.kind === "post" ? (
            <form method="POST" action={send.action}>
              {Object.entries(send.fields).map(([name, value]) => (
                <input key={name} type="hidden" name={name} value={value} />
              ))}
              <Button type="submit">
                <SendIcon data-icon="inline-start" />
                Send to the service provider
              </Button>
            </form>
          ) : (
            <a href={send.url} className={cn(buttonVariants(), "self-start")}>
              <SendIcon data-icon="inline-start" />
              Send the artifact to the service provider
            </a>
          )}
          <XmlBlock title="SAML Response" xml={view.xml} />
          <Disclosure label={view.detail.label}>
            <pre className="max-h-64 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs break-all whitespace-pre-wrap">
              {view.detail.value}
            </pre>
          </Disclosure>
        </CardContent>
      </Card>
    </div>
  )
}

function PickSpView({ view }: { view: View<"pick-sp"> }) {
  return (
    <Narrow>
      <Card>
        <CardHeader>
          <CardDescription>IdP-initiated login</CardDescription>
          <CardTitle className="text-xl">Sign in to…</CardTitle>
          <CardDescription>
            Sends an unsolicited Response (no AuthnRequest) to the service
            provider's default ACS URL. Link here with{" "}
            <code>?sp=&lt;entity ID&gt;</code> and optionally{" "}
            <code>RelayState</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {view.sps.map((sp) => (
            <Item key={sp.entity_id} variant="outline" size="sm">
              <ItemContent className="min-w-0">
                <ItemTitle>{sp.label}</ItemTitle>
                {sp.label !== sp.entity_id && (
                  <ItemDescription className="truncate font-mono text-xs">
                    {sp.entity_id}
                  </ItemDescription>
                )}
              </ItemContent>
              <ItemActions>
                <a href={sp.href} className={buttonVariants({ size: "sm" })}>
                  Sign in
                </a>
              </ItemActions>
            </Item>
          ))}
        </CardContent>
      </Card>
    </Narrow>
  )
}

function SignedOutView({ view }: { view: View<"signed-out"> }) {
  return (
    <Narrow>
      <Card>
        <CardHeader>
          <CardDescription>Single logout</CardDescription>
          <CardTitle className="text-xl">
            Signed out <span className="text-primary">{view.who}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {view.results.length ? (
            view.results.map((r) => (
              <Item key={r.sp} variant="outline" size="sm">
                <ItemContent className="min-w-0">
                  <ItemTitle className="truncate font-mono text-xs">
                    {r.sp}
                  </ItemTitle>
                </ItemContent>
                <ItemActions>
                  <Badge
                    variant={
                      r.outcome === "logged out" ? "secondary" : "outline"
                    }
                  >
                    {r.outcome}
                  </Badge>
                </ItemActions>
              </Item>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">
              No other service providers were signed in.
            </p>
          )}
        </CardContent>
        {view.returnTo && (
          <CardFooter className="border-t">
            <a
              href={view.returnTo}
              className={buttonVariants({ variant: "outline" })}
            >
              Continue
            </a>
          </CardFooter>
        )}
      </Card>
    </Narrow>
  )
}

function CheckMark({ ok }: { ok: boolean | null }) {
  if (ok === true) return <CheckIcon className="size-4 shrink-0 text-primary" />
  if (ok === false)
    return <XIcon className="size-4 shrink-0 text-destructive" />
  return <DotIcon className="size-4 shrink-0 text-muted-foreground" />
}

function SpOutcomeView({ view }: { view: View<"sp-outcome"> }) {
  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription
            className={view.passed ? undefined : "text-destructive"}
          >
            {view.verdict}
          </CardDescription>
          <CardTitle className="text-xl">{view.title}</CardTitle>
          <CardDescription>
            NameID{" "}
            {view.nameId ? (
              <>
                <code className="text-foreground">{view.nameId.value}</code>{" "}
                {short(view.nameId.format)}
              </>
            ) : (
              "–"
            )}
            {view.relayState && (
              <>
                {" "}
                · RelayState <code>{view.relayState}</code>
              </>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="flex flex-col gap-1.5 text-sm">
            {view.checks.map((c, i) => (
              <li key={i} className="flex items-start gap-2">
                <CheckMark ok={c.ok} />
                <span>
                  <b className="font-medium">{c.label}</b>{" "}
                  <span className="text-muted-foreground">{c.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        </CardContent>
        <CardFooter className="border-t">
          <a
            href={view.home}
            className={buttonVariants({ variant: "outline" })}
          >
            Back to the test SP
          </a>
        </CardFooter>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Attributes</CardTitle>
        </CardHeader>
        <CardContent>
          {view.attributes.length ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Name</TableHead>
                  <TableHead>Values</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {view.attributes.map((a) => (
                  <TableRow key={a.name}>
                    <TableCell className="font-mono text-xs break-all whitespace-normal">
                      {a.name}
                      {a.friendlyName && (
                        <span className="ml-2 font-sans text-muted-foreground">
                          {a.friendlyName}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-normal">
                      <div className="flex flex-wrap gap-1">
                        {a.values.map((v, i) => (
                          <Badge
                            key={i}
                            variant="secondary"
                            className="font-mono"
                          >
                            {v}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">No attributes.</p>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Messages</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {view.sent && (
            <XmlBlock title={view.sent.title} xml={view.sent.xml} />
          )}
          {view.responseXml && (
            <XmlBlock title="SAML Response" xml={view.responseXml} />
          )}
          {view.assertionXml && (
            <XmlBlock title="Decrypted assertion" xml={view.assertionXml} />
          )}
        </CardContent>
      </Card>
    </div>
  )
}
