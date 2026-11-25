import {
  ClockIcon,
  DownloadIcon,
  KeyRoundIcon,
  LogOutIcon,
  PlusIcon,
  RotateCcwIcon,
  Trash2Icon,
  UnplugIcon,
  WandSparklesIcon,
  XIcon,
} from "lucide-react"
import * as React from "react"
import { useLoaderData, useLocation, useRevalidator } from "react-router"
import { toast } from "sonner"

import { IdentityEditor, SaveIdentity } from "@/components/identity-editor"
import { MintResult, type MintOutcome } from "@/components/mint-result"
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
  Field,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { ApiError, api, message } from "@/lib/api"
import {
  build,
  initialEditor,
  loadIdentity,
  rememberLast,
  storedEntry,
  type EditorState,
} from "@/lib/identity"
import { prefix } from "@/lib/page"
import { useInfo } from "@/lib/root"
import type {
  EditorData,
  Entry,
  Fault,
  Info,
  Minted,
  Preset,
  ServiceProvider,
  Session,
  User,
} from "@/lib/types"

export async function devLoader() {
  const [presets, users, sps, faults, sessions] = await Promise.all([
    api<Preset[]>("/dev/api/presets"),
    api<User[]>("/dev/api/users"),
    api<ServiceProvider[]>("/dev/api/service-providers"),
    api<Fault[]>("/dev/api/faults"),
    api<Session[]>("/dev/api/sessions"),
  ])
  return { presets, users, sps, faults, sessions }
}

type DevData = Awaited<ReturnType<typeof devLoader>>

/** The assertion generator, and the service provider, certificate, clock, fault and session tools. */
export function DevPage() {
  const info = useInfo()
  const data = useLoaderData<DevData>()
  const { hash } = useLocation()

  // The warning banners (and the single logout's return) link to the sections here.
  React.useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView()
  }, [hash])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <datalist id="dev-sps">
        {data.sps.map((sp) => (
          <option key={sp.entity_id} value={sp.entity_id} />
        ))}
      </datalist>
      <Generator info={info} data={data} />
      <ServiceProvidersCard info={info} sps={data.sps} />
      <CertificateCard info={info} />
      <ClockCard info={info} />
      <FaultsCard info={info} faults={data.faults} />
      <SessionsCard sessions={data.sessions} />
    </div>
  )
}

const TRI = [
  { label: "Template default", value: "" },
  { label: "Yes", value: "true" },
  { label: "No", value: "false" },
]
const SP_TRI = [
  { label: "SP default", value: "" },
  { label: "Yes", value: "true" },
  { label: "No", value: "false" },
]
const ALGORITHMS = [
  { label: "RSA-SHA256", value: "rsa-sha256" },
  { label: "RSA-SHA512", value: "rsa-sha512" },
  { label: "RSA-SHA1", value: "rsa-sha1" },
]
const ENCRYPTION = [
  { label: "SP default", value: "" },
  { label: "No", value: "none" },
  { label: "AES-256-GCM", value: "aes256-gcm" },
  { label: "AES-128-GCM", value: "aes128-gcm" },
  { label: "AES-256-CBC", value: "aes256-cbc" },
  { label: "AES-128-CBC", value: "aes128-cbc" },
]

type Options = {
  sp: string
  acs: string
  audience: string
  inResponseTo: string
  relayState: string
  ttl: string
  signResponse: string
  signAssertion: string
  algorithm: string
  encrypt: string
  encryptNameId: string
  encryptAttributes: string
  tampers: string[]
}

function OptionSelect({
  label,
  items,
  value,
  onChange,
}: {
  label: string
  items: { label: string; value: string }[]
  value: string
  onChange: (value: string) => void
}) {
  return (
    <Field>
      <FieldLabel>{label}</FieldLabel>
      <Select
        items={items}
        value={value}
        onValueChange={(v) => onChange(v ?? "")}
      >
        <SelectTrigger className="w-full" aria-label={label}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {items.map((i) => (
            <SelectItem key={i.value} value={i.value}>
              {i.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Field>
  )
}

const tri = (v: string) => (v === "" ? undefined : v === "true")

function Generator({ info, data }: { info: Info; data: DevData }) {
  const [editorData] = React.useState<EditorData>(() => ({
    mode: "dev",
    entityId: info.entity_id,
    presets: data.presets,
    defaultPreset: info.default_preset,
    tenantPreset: info.preset?.id ?? null,
    nameIdFormats: info.name_id_formats,
    previous: null,
    users: data.users,
  }))
  const [state, setState] = React.useState(() => initialEditor(editorData))
  const [options, setOptions] = React.useState<Options>({
    sp: info.test_sp,
    acs: "",
    audience: "",
    inResponseTo: "",
    relayState: "",
    ttl: "",
    signResponse: "",
    signAssertion: "",
    algorithm: info.signature_algorithm,
    encrypt: "",
    encryptNameId: "",
    encryptAttributes: "",
    tampers: [],
  })
  const [busy, setBusy] = React.useState(false)
  const [result, setResult] = React.useState<MintOutcome | null>(null)
  const { errors } = build(data.presets, state)
  const set = <K extends keyof Options>(key: K, value: Options[K]) =>
    setOptions((o) => ({ ...o, [key]: value }))

  async function generate(editor: EditorState) {
    const { identity, errors } = build(data.presets, editor)
    if (errors.length) return
    rememberLast(storedEntry(editor, identity))
    const o = options
    const request = {
      preset: editor.preset,
      sp: o.sp.trim() || undefined,
      acs_url: o.acs.trim() || undefined,
      audience: o.audience.trim() || undefined,
      in_response_to: o.inResponseTo.trim() || undefined,
      relay_state: o.relayState || undefined,
      expires_in: Number(o.ttl) || undefined,
      sign_response: tri(o.signResponse),
      sign_assertion: tri(o.signAssertion),
      signature_algorithm: o.algorithm,
      encrypt: o.encrypt === "" ? undefined : o.encrypt !== "none",
      encryption_algorithm:
        o.encrypt && o.encrypt !== "none" ? o.encrypt : undefined,
      encrypt_name_id: tri(o.encryptNameId),
      encrypt_attributes: tri(o.encryptAttributes),
      tamper: o.tampers,
      defaults: false,
      name_id: identity.name_id || undefined,
      name_id_format: identity.name_id_format,
      attributes: identity.attributes,
    }
    setBusy(true)
    try {
      const minted = await api<Minted>("/dev/api/response", {
        method: "POST",
        body: request,
      })
      setResult({ ok: true, minted, request })
    } catch (e) {
      setResult({
        ok: false,
        message: message(e),
        data: e instanceof ApiError ? e.data : null,
      })
    } finally {
      setBusy(false)
    }
  }

  function use(entry: Entry) {
    const next = loadIdentity(state, editorData, entry.preset, entry.identity)
    setState(next)
    void generate(next)
  }

  const optionsStep = (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        Who the Response is for, how it is signed and encrypted, and any
        deliberate defects.
      </p>
      <FieldGroup className="grid gap-4 sm:grid-cols-3">
        <Field className="sm:col-span-3">
          <FieldLabel htmlFor="dev-sp">Service provider</FieldLabel>
          <Input
            id="dev-sp"
            list="dev-sps"
            className="font-mono"
            value={options.sp}
            onChange={(e) => set("sp", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-acs">ACS URL</FieldLabel>
          <Input
            id="dev-acs"
            placeholder="the SP's default ACS"
            value={options.acs}
            onChange={(e) => set("acs", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-audience">Audience</FieldLabel>
          <Input
            id="dev-audience"
            placeholder="the SP's entity ID"
            value={options.audience}
            onChange={(e) => set("audience", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-irt">InResponseTo</FieldLabel>
          <Input
            id="dev-irt"
            placeholder="none: unsolicited"
            value={options.inResponseTo}
            onChange={(e) => set("inResponseTo", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-relay">RelayState</FieldLabel>
          <Input
            id="dev-relay"
            placeholder="optional"
            value={options.relayState}
            onChange={(e) => set("relayState", e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="dev-ttl">Lifetime (s)</FieldLabel>
          <Input
            id="dev-ttl"
            type="number"
            placeholder={String(info.assertion_lifetime)}
            value={options.ttl}
            onChange={(e) => set("ttl", e.target.value)}
          />
        </Field>
        <OptionSelect
          label="Signature algorithm"
          items={ALGORITHMS}
          value={options.algorithm}
          onChange={(v) => set("algorithm", v)}
        />
        <OptionSelect
          label="Sign response"
          items={TRI}
          value={options.signResponse}
          onChange={(v) => set("signResponse", v)}
        />
        <OptionSelect
          label="Sign assertion"
          items={TRI}
          value={options.signAssertion}
          onChange={(v) => set("signAssertion", v)}
        />
        <OptionSelect
          label="Encrypt assertion"
          items={ENCRYPTION}
          value={options.encrypt}
          onChange={(v) => set("encrypt", v)}
        />
        <OptionSelect
          label="Encrypt NameID"
          items={SP_TRI}
          value={options.encryptNameId}
          onChange={(v) => set("encryptNameId", v)}
        />
        <OptionSelect
          label="Encrypt attributes"
          items={SP_TRI}
          value={options.encryptAttributes}
          onChange={(v) => set("encryptAttributes", v)}
        />
      </FieldGroup>
      <FieldSet>
        <FieldLegend variant="label">Defects</FieldLegend>
        <div className="grid gap-x-4 gap-y-2 sm:grid-cols-3">
          {info.tampers.map((t) => (
            <Tooltip key={t.name}>
              <TooltipTrigger
                render={<Field orientation="horizontal" className="w-fit" />}
              >
                <Checkbox
                  id={`tamper-${t.name}`}
                  checked={options.tampers.includes(t.name)}
                  onCheckedChange={(on) =>
                    set(
                      "tampers",
                      on
                        ? [...options.tampers, t.name]
                        : options.tampers.filter((x) => x !== t.name)
                    )
                  }
                />
                <FieldLabel
                  htmlFor={`tamper-${t.name}`}
                  className="font-mono text-xs"
                >
                  {t.name}
                </FieldLabel>
              </TooltipTrigger>
              <TooltipContent>{t.description}</TooltipContent>
            </Tooltip>
          ))}
        </div>
      </FieldSet>
    </div>
  )

  return (
    <>
      <Card>
        <CardHeader>
          <CardDescription>Assertion generator</CardDescription>
          <CardTitle className="text-xl">
            Mint SAML responses as{" "}
            <span className="font-mono text-primary">{info.entity_id}</span>
          </CardTitle>
          <CardDescription>
            Build a signed Response without a browser login, then post it to
            your ACS from here or paste it into a test. Scripts and tests can
            use the same thing via{" "}
            <code>
              POST{" "}
              {
                info.endpoints.find((e) => e.url.endsWith("/dev/api/response"))
                  ?.url
              }
            </code>
            .
          </CardDescription>
        </CardHeader>
        <CardContent>
          <IdentityEditor
            data={editorData}
            state={state}
            setState={setState}
            onUse={use}
            options={optionsStep}
          />
        </CardContent>
        <CardFooter className="flex flex-wrap justify-between gap-3 border-t">
          <Button
            disabled={busy || errors.length > 0}
            onClick={() => void generate(state)}
          >
            <WandSparklesIcon data-icon="inline-start" />
            Generate response
          </Button>
          <SaveIdentity data={editorData} state={state} />
        </CardFooter>
      </Card>
      {result && <MintResult result={result} />}
    </>
  )
}

function ServiceProvidersCard({
  info,
  sps,
}: {
  info: Info
  sps: ServiceProvider[]
}) {
  const { revalidate } = useRevalidator()
  const [metadata, setMetadata] = React.useState("")
  const [busy, setBusy] = React.useState(false)

  async function register() {
    const text = metadata.trim()
    if (!text) return
    setBusy(true)
    try {
      // Pasted metadata is sent as XML; a URL is fetched by localsaml.
      if (text.startsWith("<")) {
        const response = await fetch(`${prefix}/dev/api/service-providers`, {
          method: "POST",
          headers: { "content-type": "application/xml" },
          body: text,
        })
        if (!response.ok) {
          const error = (await response.json().catch(() => ({}))) as {
            error_description?: string
          }
          throw new Error(error.error_description ?? response.statusText)
        }
      } else {
        await api("/dev/api/service-providers", {
          method: "POST",
          body: { metadata_url: text },
        })
      }
      setMetadata("")
      toast("Service provider registered")
      await revalidate()
    } catch (e) {
      toast.error(`Registering the service provider failed: ${message(e)}`)
    } finally {
      setBusy(false)
    }
  }

  async function remove(entityId: string) {
    try {
      await api(
        `/dev/api/service-providers?entity_id=${encodeURIComponent(entityId)}`,
        { method: "DELETE" }
      )
      await revalidate()
    } catch (e) {
      toast.error(`Removing the service provider failed: ${message(e)}`)
    }
  }

  return (
    <Card id="sps" className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Service providers</CardDescription>
        <CardTitle>
          {sps.length}{" "}
          {sps.length === 1 ? "service provider" : "service providers"}
        </CardTitle>
        <CardDescription>
          localsaml answers the service providers listed here, and ones whose
          metadata it can fetch from their entity ID
          {info.lenient &&
            " (and, in lenient mode, any other, with the ACS URL from its AuthnRequest)"}
          . Declare one in <code>localsaml.toml</code>, or register it here from
          its metadata, so its ACS URLs can be verified, its signatures checked,
          assertions encrypted for it and it can be logged out.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <div className="flex flex-col gap-2">
          {sps.map((sp) => {
            const label = sp.name ?? sp.entity_id
            return (
              <Item key={sp.entity_id} variant="outline" size="sm">
                <ItemContent className="min-w-0">
                  <ItemTitle className="w-full min-w-0">
                    <span className="truncate">{label}</span>
                    {sp.metadata_pending && (
                      <Badge
                        variant="outline"
                        className="text-muted-foreground"
                      >
                        metadata not loaded yet
                      </Badge>
                    )}
                  </ItemTitle>
                  <ItemDescription className="flex flex-col gap-0.5 font-mono text-xs break-all">
                    {label !== sp.entity_id && <span>{sp.entity_id}</span>}
                    <span>
                      ACS{" "}
                      {sp.acs_urls.length
                        ? sp.acs_urls.join(", ")
                        : "from requests"}
                    </span>
                    {sp.slo_url && <span>SLO {sp.slo_url}</span>}
                    {sp.certificate && <span>certificate</span>}
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  {sp.source === "api" ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => void remove(sp.entity_id)}
                    >
                      <XIcon data-icon="inline-start" />
                      Remove
                    </Button>
                  ) : (
                    <Badge variant="secondary">{sp.source}</Badge>
                  )}
                </ItemActions>
              </Item>
            )
          })}
        </div>
        <Field>
          <FieldLabel htmlFor="sp-metadata">Metadata URL or XML</FieldLabel>
          <Textarea
            id="sp-metadata"
            rows={3}
            spellCheck={false}
            className="font-mono text-xs"
            placeholder="http://localhost:3000/saml/metadata, or paste <EntityDescriptor …>"
            value={metadata}
            onChange={(e) => setMetadata(e.target.value)}
          />
        </Field>
      </CardContent>
      <CardFooter className="border-t">
        <Button
          variant="outline"
          disabled={busy || !metadata.trim()}
          onClick={() => void register()}
        >
          <PlusIcon data-icon="inline-start" />
          Register service provider
        </Button>
      </CardFooter>
    </Card>
  )
}

function CertificateCard({ info }: { info: Info }) {
  const { revalidate } = useRevalidator()
  const [busy, setBusy] = React.useState(false)
  const cert = info.certificate

  async function rotate() {
    setBusy(true)
    try {
      await api("/dev/api/rotate-keys", { method: "POST" })
      toast("Rotated: a new key and certificate")
      await revalidate()
    } catch (e) {
      toast.error(`Key rotation failed: ${message(e)}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card id="certificate" className="scroll-mt-6">
      <CardHeader>
        <CardDescription className="flex items-center gap-1.5">
          <KeyRoundIcon className="size-3.5" />
          Signing certificate
        </CardDescription>
        <CardTitle className="font-mono text-sm break-all">
          {cert.subject}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
          {[
            ["Valid", `${cert.not_before} to ${cert.not_after}`],
            ["SHA-1 fingerprint", cert.sha1_fingerprint],
            ["SHA-256 fingerprint", cert.sha256_fingerprint],
          ].map(([term, value]) => (
            <div key={term} className="contents">
              <dt className="text-muted-foreground">{term}</dt>
              <dd className="font-mono text-xs break-all">{value}</dd>
            </div>
          ))}
        </dl>
        <p className="text-sm text-muted-foreground">
          Rotating creates a new key and certificate. The previous{" "}
          {info.retired_keys_kept} stay in the{" "}
          <a
            href={`${prefix}/metadata`}
            className="underline underline-offset-4"
          >
            metadata
          </a>
          , so service providers that refresh it keep trusting responses; ones
          configured with a pinned certificate or fingerprint stop.
        </p>
      </CardContent>
      <CardFooter className="gap-2 border-t">
        <a
          href={`${prefix}/certificate.pem`}
          download="localsaml.pem"
          className={buttonVariants({ variant: "ghost" })}
        >
          <DownloadIcon data-icon="inline-start" />
          Download certificate (PEM)
        </a>
        <Button variant="outline" disabled={busy} onClick={() => void rotate()}>
          <RotateCcwIcon data-icon="inline-start" />
          Rotate signing key
        </Button>
      </CardFooter>
    </Card>
  )
}

const AMOUNT_KEY = "localsaml.clockAmount"

function ClockCard({ info }: { info: Info }) {
  const { revalidate } = useRevalidator()
  const [amount, setAmount] = React.useState(() => {
    try {
      return sessionStorage.getItem(AMOUNT_KEY) ?? "10m"
    } catch {
      return "10m"
    }
  })
  const offset = info.clock.offset

  async function shift(body: object) {
    try {
      const clock = await api<Info["clock"]>("/dev/api/clock", {
        method: "POST",
        body,
      })
      try {
        sessionStorage.setItem(AMOUNT_KEY, amount)
      } catch {
        // Not kept.
      }
      toast(
        clock.offset
          ? `The clock is now ${clock.offset_text} ${clock.offset > 0 ? "ahead of" : "behind"} real time`
          : "The clock is back on real time"
      )
      await revalidate()
    } catch (e) {
      toast.error(`Changing the clock failed: ${message(e)}`)
    }
  }
  const by = () => amount.trim().replace(/^[+-]/, "")

  return (
    <Card id="clock" className="scroll-mt-6">
      <CardHeader>
        <CardDescription className="flex items-center gap-1.5">
          <ClockIcon className="size-3.5" />
          Clock
        </CardDescription>
        <CardTitle>
          {offset === 0 ? (
            "The clock runs on real time"
          ) : (
            <>
              The clock is{" "}
              <span className="text-primary">{info.clock.offset_text}</span>{" "}
              {offset > 0 ? "ahead of" : "behind"} real time
            </>
          )}
        </CardTitle>
        <CardDescription>
          Shift it to issue assertions that look expired or not yet valid to
          your app (whose clock is real), or to expire localsaml's sessions
          without waiting.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        <Input
          aria-label="Duration, e.g. 15m, 2h, 31d"
          className="w-28 font-mono"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
        <Button variant="outline" onClick={() => void shift({ advance: by() })}>
          Move forward
        </Button>
        <Button
          variant="outline"
          onClick={() => void shift({ advance: `-${by()}` })}
        >
          Move back
        </Button>
        <Button
          variant="ghost"
          disabled={offset === 0}
          onClick={() => void shift({ reset: true })}
        >
          <RotateCcwIcon data-icon="inline-start" />
          Reset to real time
        </Button>
      </CardContent>
    </Card>
  )
}

const ENDPOINTS = ["sso", "slo", "metadata"].map((e) => ({
  label: e,
  value: e,
}))

function FaultsCard({ info, faults }: { info: Info; faults: Fault[] }) {
  const { revalidate } = useRevalidator()
  const [endpoint, setEndpoint] = React.useState("sso")
  const [status, setStatus] = React.useState("")
  const [tamper, setTamper] = React.useState("")
  const [sp, setSp] = React.useState("")
  const [http, setHttp] = React.useState("")
  const [delay, setDelay] = React.useState("0")
  const [count, setCount] = React.useState("1")
  const [always, setAlways] = React.useState(false)
  // Each endpoint takes different fields; hidden ones aren't sent.
  const saml = endpoint === "sso" || endpoint === "slo"

  async function change(method: string, path: string, body?: object) {
    try {
      await api(path, { method, body })
      await revalidate()
    } catch (e) {
      toast.error(`Changing faults failed: ${message(e)}`)
    }
  }

  function arm() {
    const body: Record<string, unknown> = { endpoint }
    if (saml && status.trim()) body.status = status.trim()
    if (endpoint === "sso" && tamper) body.tamper = [tamper]
    if (saml && sp.trim()) body.sp = sp.trim()
    if (endpoint === "metadata" && Number(http)) body.http_status = Number(http)
    if (Number(delay)) body.delay_ms = Number(delay)
    if (always) body.always = true
    else body.count = Math.max(1, Number(count) || 1)
    void change("POST", "/dev/api/faults", body)
  }

  const tamperItems = [
    { label: "none", value: "" },
    ...info.tampers.map((t) => ({ label: t.name, value: t.name })),
  ]
  const left = (f: Fault) =>
    f.remaining == null
      ? "until removed"
      : f.remaining === 1
        ? "next request"
        : `next ${f.remaining} requests`

  return (
    <Card id="faults" className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Faults</CardDescription>
        <CardTitle>
          {faults.length ? `${faults.length} armed` : "No faults armed"}
        </CardTitle>
        <CardDescription>
          Make the next logins fail with a SAML error status, carry a
          deliberately defective Response, or respond slowly; or make metadata
          unavailable. Errors go back to the service provider like real ones.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {faults.length > 0 && (
          <div className="flex flex-col gap-2">
            {faults.map((f) => (
              <Item key={f.id} variant="outline" size="sm">
                <ItemContent>
                  <ItemTitle className="font-mono">{f.endpoint}</ItemTitle>
                  <ItemDescription className="text-xs">
                    {[
                      f.summary || "no error",
                      f.sp && `SP ${f.sp}`,
                      f.issuer && `issuer ${f.issuer}`,
                      left(f),
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      void change("DELETE", `/dev/api/faults/${f.id}`)
                    }
                  >
                    <XIcon data-icon="inline-start" />
                    Remove
                  </Button>
                </ItemActions>
              </Item>
            ))}
          </div>
        )}
        <FieldGroup className="grid gap-4 sm:grid-cols-3">
          <OptionSelect
            label="Endpoint"
            items={ENDPOINTS}
            value={endpoint}
            onChange={setEndpoint}
          />
          {saml && (
            <Field>
              <FieldLabel htmlFor="fault-status">SAML status</FieldLabel>
              <Input
                id="fault-status"
                list="fault-statuses"
                placeholder="e.g. AuthnFailed"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              />
              <datalist id="fault-statuses">
                {info.fault_statuses.map((s) => (
                  <option key={s} value={s} />
                ))}
              </datalist>
            </Field>
          )}
          {endpoint === "sso" && (
            <OptionSelect
              label="Defect"
              items={tamperItems}
              value={tamper}
              onChange={setTamper}
            />
          )}
          {saml && (
            <Field>
              <FieldLabel htmlFor="fault-sp">Service provider</FieldLabel>
              <Input
                id="fault-sp"
                list="dev-sps"
                placeholder="any"
                value={sp}
                onChange={(e) => setSp(e.target.value)}
              />
            </Field>
          )}
          {endpoint === "metadata" && (
            <Field>
              <FieldLabel htmlFor="fault-http">HTTP status</FieldLabel>
              <Input
                id="fault-http"
                type="number"
                min={400}
                max={599}
                placeholder="503"
                value={http}
                onChange={(e) => setHttp(e.target.value)}
              />
            </Field>
          )}
          <Field>
            <FieldLabel htmlFor="fault-delay">Delay (ms)</FieldLabel>
            <Input
              id="fault-delay"
              type="number"
              min={0}
              max={info.max_fault_delay_ms}
              value={delay}
              onChange={(e) => setDelay(e.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="fault-count">Times</FieldLabel>
            <Input
              id="fault-count"
              type="number"
              min={1}
              disabled={always}
              value={count}
              onChange={(e) => setCount(e.target.value)}
            />
          </Field>
          <Field orientation="horizontal" className="self-end pb-2">
            <Checkbox
              id="fault-always"
              checked={always}
              onCheckedChange={setAlways}
            />
            <FieldLabel htmlFor="fault-always">Until removed</FieldLabel>
          </Field>
        </FieldGroup>
      </CardContent>
      <CardFooter className="gap-2 border-t">
        <Button variant="outline" onClick={arm}>
          <PlusIcon data-icon="inline-start" />
          Arm fault
        </Button>
        <Button
          variant="ghost"
          disabled={!faults.length}
          onClick={() => void change("DELETE", "/dev/api/faults")}
        >
          <Trash2Icon data-icon="inline-start" />
          Remove all
        </Button>
      </CardFooter>
    </Card>
  )
}

type Ended = {
  deliveries: { sp: string; outcome: string; ok: boolean }[]
  not_notified: string[]
}

function SessionsCard({ sessions }: { sessions: Session[] }) {
  const { revalidate } = useRevalidator()
  const [ending, setEnding] = React.useState<string | null>(null)

  async function end(sid: string) {
    setEnding(sid)
    try {
      const result = await api<Ended>(
        `/dev/api/sessions/${encodeURIComponent(sid)}`,
        {
          method: "DELETE",
        }
      )
      const failed = result.deliveries.filter((d) => !d.ok)
      if (failed.length) {
        toast.error(
          `Session ended, but ${failed.length} back-channel ${failed.length === 1 ? "logout" : "logouts"} failed`,
          { description: failed.map((d) => `${d.sp}: ${d.outcome}`).join("\n") }
        )
      } else {
        toast("Session ended")
      }
      await revalidate()
    } catch (e) {
      toast.error(`Ending the session failed: ${message(e)}`)
    } finally {
      setEnding(null)
    }
  }

  const returnTo = encodeURIComponent(`${prefix}/dev#sessions`)
  return (
    <Card id="sessions" className="scroll-mt-6">
      <CardHeader>
        <CardDescription>Sessions</CardDescription>
        <CardTitle>
          {sessions.length
            ? `${sessions.length} active ${sessions.length === 1 ? "session" : "sessions"}`
            : "No active sessions"}
        </CardTitle>
        <CardDescription>
          Browser sessions on every issuer. <b>Single logout</b> ends one in
          this browser and sends a LogoutRequest to each service provider that
          used it, one after another. <b>End (back-channel)</b> ends it as if
          the user logged out elsewhere: service providers with a SOAP
          SingleLogoutService get a LogoutRequest back-channel, the others
          aren't told.
        </CardDescription>
      </CardHeader>
      {sessions.length > 0 && (
        <CardContent className="flex flex-col gap-2">
          {sessions.map((s) => (
            <Item key={s.sid} variant="outline" size="sm">
              <ItemContent className="min-w-0">
                <ItemTitle className="flex-wrap">
                  {s.who}
                  <span className="font-normal text-muted-foreground">
                    · {s.preset} ·
                  </span>
                  {s.service_providers.length ? (
                    s.service_providers.map((sp) => (
                      <Badge key={sp} variant="secondary" className="font-mono">
                        {sp}
                      </Badge>
                    ))
                  ) : (
                    <span className="font-normal text-muted-foreground">
                      no service providers
                    </span>
                  )}
                </ItemTitle>
                <ItemDescription className="truncate font-mono text-xs">
                  SessionIndex {s.session_index} · {s.issuer}
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                <a
                  href={`${s.logout_url}&return_to=${returnTo}`}
                  className={buttonVariants({ variant: "outline", size: "sm" })}
                >
                  <LogOutIcon data-icon="inline-start" />
                  Single logout
                </a>
                <Tooltip>
                  <TooltipTrigger
                    render={
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={ending === s.sid}
                        onClick={() => void end(s.sid)}
                      />
                    }
                  >
                    <UnplugIcon data-icon="inline-start" />
                    End (back-channel)
                  </TooltipTrigger>
                  <TooltipContent>
                    End it now: SPs with a SOAP SingleLogoutService are logged
                    out back-channel, others aren't told
                  </TooltipContent>
                </Tooltip>
              </ItemActions>
            </Item>
          ))}
        </CardContent>
      )}
    </Card>
  )
}
