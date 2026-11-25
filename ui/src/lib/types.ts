/** Attribute values: one string, or a list. */
export type Attributes = Record<string, string | string[]>

/** An attribute a template's editor shows. */
export type AttributeField = {
  name: string
  label: string
  friendly_name?: string
  name_format?: string
  /** `string` (one value) or `list` (any number). */
  kind: "string" | "list"
  default: unknown
  help?: string
  /** Tucked behind "Show all attributes". */
  advanced?: boolean
}

export type Preset = {
  id: string
  name: string
  description: string
  color: string
  name_id_format: string
  /** The attribute the NameID follows, if any. */
  name_id_from: string | null
  name_id_example: string
  email_attribute: string | null
  attributes: AttributeField[]
  send_empty_attributes: boolean
  style: {
    assertion_prefix: string
    name_format: string | null
    xsi_type: string | null
  }
}

/** Who to sign in (or mint a Response) as. */
export type Identity = {
  name_id: string
  name_id_format: string
  attributes: Attributes
}

/** An identity with the template it was made with, as saved and remembered. */
export type Entry = { preset: string; identity: Identity }

/** A user declared in localsaml.toml. */
export type User = {
  id: string
  label: string | null
  preset: string
  identity: Identity
}

/** What the attribute editor needs: the server sends it with the sign-in page. */
export type EditorData = {
  mode: "login" | "dev"
  entityId: string
  presets: Preset[]
  defaultPreset: string
  /** The template a `/p/<template>` issuer emulates. */
  tenantPreset: string | null
  nameIdFormats: string[]
  /** This browser's session on the issuer, if any. */
  previous: (Identity & { preset: string }) | null
  users: User[]
  loginHint?: string | null
  /** The subject an AuthnRequest names: only it gets an assertion. */
  subject?: { nameId: string; format: string | null } | null
  requestedNameIdFormat?: string | null
}

export type Clock = {
  now: number
  offset: number
  offset_text: string
  real_now: number
}

export type Certificate = {
  kid: string
  subject: string
  not_before: string
  not_after: string
  sha1_fingerprint: string
  sha256_fingerprint: string
}

export type Info = {
  version: string
  entity_id: string
  prefix: string
  metadata_url: string
  preset: { id: string; name: string; color: string } | null
  default_preset: string
  lenient: boolean
  clock: Clock
  faults_armed: number
  certificate: Certificate
  retired_keys_kept: number
  endpoints: { label: string; url: string }[]
  issuers: {
    id: string | null
    name: string
    description: string
    color?: string
    entity_id: string
    prefix: string
  }[]
  test_sp: string
  name_id_formats: string[]
  assertion_lifetime: number
  signature_algorithm: string
  fault_statuses: string[]
  tampers: { name: string; description: string }[]
  max_fault_delay_ms: number
  requests_capacity: number
}

export type ServiceProvider = {
  entity_id: string
  name?: string | null
  acs_urls: string[]
  slo_url?: string | null
  certificate?: string | null
  metadata_url?: string | null
  metadata_pending?: boolean
  /** Where it's declared: `config`, `api` (registered here), `discovered`, `built-in`… */
  source: string
}

export type Fault = {
  id: number
  endpoint: string
  issuer?: string
  sp?: string
  delay_ms: number
  remaining: number | null
  summary: string
}

export type Session = {
  sid: string
  issuer: string
  tenant: string
  who: string
  name_id: string
  preset: string
  session_index: string
  auth_time: number
  expires_at: number | null
  service_providers: string[]
  logout_url: string
}

export type SamlMessage = {
  direction: "received" | "sent"
  kind: string
  binding: string
  destination?: string
  status?: string
  xml: string
}

export type RequestEntry = {
  id: number
  at: number
  duration_ms: number
  method: string
  path: string
  issuer: string
  endpoint: string
  category: string
  sp?: string
  params: Record<string, string>
  status: number
  error?: string
  error_description?: string
  outcome: string
  redirect?: string
  outgoing?: boolean
  messages: SamlMessage[]
}

/** The Response API's answer. */
export type Minted = {
  sp: string
  acs_url: string
  relay_state?: string | null
  saml_response: string
  pretty: string
  curl: string
  name_id: string
  name_id_format: string
  signed: { response: boolean; assertion: boolean }
  encrypted: boolean
  name_id_encrypted: boolean
  attributes_encrypted: boolean
}

export type TestSp = {
  entity_id: string
  metadata: string
  acs: string
  login: string
  logout: string
  attributes: string
  initiate: string
  name_id_formats: string[]
  authn_contexts: string[]
  session: {
    name_id: string
    format: string
    session_index?: string | null
  } | null
}

type Detail = { label: string; value: string; code: boolean }

/** Which protocol page the server rendered, with what it needs. */
export type ProtocolView =
  | {
      kind: "login"
      action: string
      req: string
      sp: string
      chips: { label: string; tone: "" | "ok" | "warn" }[]
      details: Detail[]
      warnings: string[]
      requestXml: string | null
      editor: EditorData
    }
  | {
      kind: "review"
      sp: string
      acs: string
      how: string
      send:
        | { kind: "post"; action: string; fields: Record<string, string> }
        | { kind: "link"; url: string }
      xml: string
      detail: { label: string; value: string }
    }
  | {
      kind: "pick-sp"
      sps: { label: string; entity_id: string; href: string }[]
    }
  | {
      kind: "signed-out"
      who: string
      results: { sp: string; outcome: string }[]
      returnTo: string | null
    }
  | {
      kind: "sp-outcome"
      passed: boolean
      verdict: string
      title: string
      nameId: { value: string; format: string } | null
      relayState: string | null
      sent: { title: string; xml: string } | null
      checks: { ok: boolean | null; label: string; detail: string }[]
      attributes: {
        name: string
        friendlyName: string | null
        values: string[]
      }[]
      responseXml: string
      assertionXml: string | null
      home: string
    }
  | { kind: "message"; title: string; detail: string }
  | { kind: "error"; label: string; title: string; detail: string }
