import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  PencilIcon,
  RotateCcwIcon,
  SaveIcon,
  Trash2Icon,
} from "lucide-react"
import * as React from "react"

import { XmlBlock } from "@/components/xml-block"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  build,
  describe,
  entryKey,
  lastIdentity,
  loadIdentity,
  nameIdSource,
  presetOf,
  previewXml,
  saveIdentity,
  savedIdentities,
  short,
  storedEntry,
  NAME_ID,
  type EditorState,
} from "@/lib/identity"
import { useStore } from "@/lib/store"
import type { AttributeField, EditorData, Entry, Preset } from "@/lib/types"
import { cn } from "@/lib/utils"

/** A template's colour, as a dot beside its name. */
export function PresetDot({ color }: { color?: string }) {
  return (
    <span
      aria-hidden
      className="inline-block size-2 shrink-0 rounded-full bg-muted-foreground"
      style={color ? { backgroundColor: color } : undefined}
    />
  )
}

type QuickItem = {
  kind: "session" | "user" | "last" | "saved"
  label: string
  entry: Entry
}

type SetState = React.Dispatch<React.SetStateAction<EditorState>>

/**
 * The attribute editor: identities to reuse in one click, and a short wizard (template →
 * attributes → subject and custom attributes, and response options when minting) for a new one.
 * `onUse` signs in (or mints) as an identity; the page's own buttons use the editor's contents.
 */
export function IdentityEditor({
  data,
  state,
  setState,
  onUse,
  options,
}: {
  data: EditorData
  state: EditorState
  setState: SetState
  onUse: (entry: Entry) => void
  /** The assertion generator's options, as a last step. */
  options?: React.ReactNode
}) {
  const isDev = data.mode === "dev"
  const steps = [
    "Template",
    "Attributes",
    "Subject & custom",
    ...(options ? ["Response options"] : []),
  ]
  const { errors } = build(data.presets, state)
  const edit = (entry: Entry) =>
    setState((s) => ({
      ...loadIdentity(s, data, entry.preset, entry.identity),
      step: 1,
    }))

  return (
    <div className="flex flex-col gap-6">
      <QuickList data={data} onUse={onUse} onEdit={edit} />
      <section className="flex flex-col gap-4">
        <h2 className="text-sm font-medium">
          {isDev ? "New response" : "New identity"}
        </h2>
        <Tabs
          value={String(state.step)}
          onValueChange={(value: string) =>
            setState((s) => ({ ...s, step: Number(value) }))
          }
        >
          <TabsList variant="line" className="w-full justify-start">
            {steps.map((label, i) => (
              <TabsTrigger key={label} value={String(i)} className="flex-none">
                <span
                  className={cn(
                    "flex size-5 items-center justify-center rounded-full border text-xs tabular-nums",
                    i < state.step &&
                      "border-primary bg-primary text-primary-foreground",
                    i === state.step && "border-primary text-primary"
                  )}
                >
                  {i < state.step ? <CheckIcon className="size-3" /> : i + 1}
                </span>
                {label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <div>
          {state.step === 0 && (
            <TemplateStep data={data} state={state} setState={setState} />
          )}
          {state.step === 1 && (
            <AttributesStep
              preset={presetOf(data.presets, state.preset)}
              state={state}
              setState={setState}
            />
          )}
          {state.step === 2 && (
            <SubjectStep data={data} state={state} setState={setState} />
          )}
          {state.step === 3 && options}
        </div>
        <div className="flex items-center justify-between">
          {state.step > 0 ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setState((s) => ({ ...s, step: s.step - 1 }))}
            >
              <ArrowLeftIcon data-icon="inline-start" />
              Back
            </Button>
          ) : (
            <span />
          )}
          {state.step < steps.length - 1 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setState((s) => ({ ...s, step: s.step + 1 }))}
            >
              Next: {steps[state.step + 1]}
              <ArrowRightIcon data-icon="inline-end" />
            </Button>
          )}
        </div>
      </section>
      {errors.length > 0 && (
        <Alert variant="destructive">
          <AlertDescription>{errors.join(" · ")}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

/** The session, declared users, the last identity used and saved ones, for one-click reuse. */
function QuickList({
  data,
  onUse,
  onEdit,
}: {
  data: EditorData
  onUse: (entry: Entry) => void
  onEdit: (entry: Entry) => void
}) {
  const saved = useStore(savedIdentities)
  const isDev = data.mode === "dev"
  const items: QuickItem[] = []
  if (data.previous && !isDev) {
    items.push({
      kind: "session",
      label: "Active session",
      entry: { preset: data.previous.preset, identity: data.previous },
    })
  }
  for (const u of data.users) {
    items.push({
      kind: "user",
      label: u.label ?? u.id,
      entry: { preset: u.preset, identity: u.identity },
    })
  }
  // "Last used" only when it isn't already offered as the session, a user or a saved identity.
  const last = lastIdentity()
  const offered = new Set([
    ...items.map((i) => entryKey(i.entry)),
    ...saved.map(entryKey),
  ])
  if (last?.identity && !offered.has(entryKey(last))) {
    items.push({ kind: "last", label: "Last used", entry: last })
  }
  for (const s of saved) items.push({ kind: "saved", label: s.name, entry: s })

  // An AuthnRequest naming a Subject only gets an assertion about that subject (Profiles 4.1.4.1).
  const subject = data.subject?.nameId
  const mismatch = (e: Entry) =>
    !!subject && !!e.identity.name_id && e.identity.name_id !== subject

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium">
        {isDev ? "Saved identities" : "Quick sign in"}
      </h2>
      {subject && !isDev && (
        <Alert>
          <AlertDescription>
            <span>
              This request is for the subject{" "}
              <code className="font-mono text-foreground">{subject}</code>. Only
              signing in with that NameID (filled in below) gets an assertion;
              any other identity gets an UnknownPrincipal error.
            </span>
          </AlertDescription>
        </Alert>
      )}
      {items.length ? (
        <div className="flex flex-col gap-2">
          {items.map((item) => {
            const p = presetOf(data.presets, item.entry.preset)
            const who = describe(data.presets, item.entry)
            const named = item.kind === "saved" || item.kind === "user"
            return (
              <Item
                key={`${item.kind}:${item.label}:${entryKey(item.entry)}`}
                variant="outline"
                size="sm"
              >
                <ItemContent className="min-w-0">
                  <ItemTitle className="w-full min-w-0">
                    <span className="truncate">
                      {named ? (
                        item.label
                      ) : (
                        <>
                          <span className="text-muted-foreground">
                            {item.label}
                          </span>{" "}
                          · {who}
                        </>
                      )}
                    </span>
                    {item.kind === "user" && (
                      <Tooltip>
                        <TooltipTrigger
                          render={<Badge variant="secondary">config</Badge>}
                        />
                        <TooltipContent>
                          Declared in localsaml.toml
                        </TooltipContent>
                      </Tooltip>
                    )}
                    {mismatch(item.entry) && (
                      <Badge variant="destructive">
                        not the requested subject
                      </Badge>
                    )}
                  </ItemTitle>
                  <ItemDescription className="flex items-center gap-1.5 text-xs">
                    <PresetDot color={p.color} />
                    <span className="truncate">
                      {p.name}
                      {named && item.label !== who ? ` · ${who}` : ""}
                    </span>
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Button
                    size="sm"
                    aria-label={`${isDev ? "Generate" : "Sign in"}: ${item.label} (${who})`}
                    onClick={() => onUse(item.entry)}
                  >
                    {isDev ? "Generate" : "Sign in"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={`Edit: ${item.label} (${who})`}
                    onClick={() => onEdit(item.entry)}
                  >
                    <PencilIcon data-icon="inline-start" />
                    Edit
                  </Button>
                  {item.kind === "saved" && (
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Delete ${item.label}`}
                      onClick={() =>
                        savedIdentities.set((list) =>
                          list.filter((s) => s.name !== item.label)
                        )
                      }
                    >
                      <Trash2Icon />
                    </Button>
                  )}
                </ItemActions>
              </Item>
            )
          })}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          Identities you save show up here for one-click reuse.
        </p>
      )}
    </section>
  )
}

type StepProps = { state: EditorState; setState: SetState }

function TemplateStep({
  data,
  state,
  setState,
}: StepProps & { data: EditorData }) {
  const pinned = data.tenantPreset
    ? presetOf(data.presets, data.tenantPreset)
    : null
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        Which identity provider should this look like? This sets the attribute
        names, NameID, signing and XML style.
        {pinned && ` This issuer emulates ${pinned.name}.`}
      </p>
      <RadioGroup
        aria-label="Template"
        value={state.preset}
        onValueChange={(id: string) =>
          setState((s) => ({
            ...(id === s.preset ? s : loadIdentity(s, data, id, null)),
            step: 1,
          }))
        }
        className="grid gap-2 sm:grid-cols-2"
      >
        {data.presets.map((p) => (
          <FieldLabel key={p.id} htmlFor={`preset-${p.id}`}>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldTitle>
                  <PresetDot color={p.color} />
                  {p.name}
                </FieldTitle>
                <FieldDescription className="text-xs">
                  {p.description}
                </FieldDescription>
              </FieldContent>
              <RadioGroupItem value={p.id} id={`preset-${p.id}`} />
            </Field>
          </FieldLabel>
        ))}
      </RadioGroup>
    </div>
  )
}

function AttributesStep({
  preset,
  state,
  setState,
}: StepProps & { preset: Preset }) {
  const common = preset.attributes.filter((a) => !a.advanced)
  const advanced = preset.attributes.filter((a) => a.advanced)
  const set = (name: string, value: string) =>
    setState((s) => ({ ...s, values: { ...s.values, [name]: value } }))
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {preset.name} attributes. Empty ones are left out of the assertion.
      </p>
      <FieldGroup className="grid gap-4 sm:grid-cols-2">
        {common.map((a) => (
          <AttributeInput
            key={a.name}
            field={a}
            value={state.values[a.name] ?? ""}
            onChange={set}
          />
        ))}
      </FieldGroup>
      {advanced.length > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className="self-start"
          onClick={() => setState((s) => ({ ...s, showAll: !s.showAll }))}
        >
          {state.showAll
            ? "Hide extra attributes"
            : `Show all attributes (${advanced.length} more)`}
        </Button>
      )}
      {state.showAll && advanced.length > 0 && (
        <FieldGroup className="grid gap-4 sm:grid-cols-2">
          {advanced.map((a) => (
            <AttributeInput
              key={a.name}
              field={a}
              value={state.values[a.name] ?? ""}
              onChange={set}
            />
          ))}
        </FieldGroup>
      )}
    </div>
  )
}

function AttributeInput({
  field: a,
  value,
  onChange,
}: {
  field: AttributeField
  value: string
  onChange: (name: string, value: string) => void
}) {
  const id = `attr-${a.name.replace(/[^a-z0-9]/gi, "_")}`
  const wide = a.kind === "list" || a.name.length > 40
  return (
    <Field className={cn(wide && "sm:col-span-2")}>
      <FieldLabel htmlFor={id} className="flex-wrap">
        {a.label}
        <code
          title={a.name}
          className="truncate font-mono text-xs font-normal text-muted-foreground"
        >
          {a.friendly_name ?? a.name}
        </code>
      </FieldLabel>
      {a.kind === "list" ? (
        <Textarea
          id={id}
          rows={Math.max(2, value.split("\n").length)}
          spellCheck={false}
          placeholder="one value per line"
          className="font-mono text-xs"
          value={value}
          onChange={(e) => onChange(a.name, e.target.value)}
        />
      ) : (
        <Input
          id={id}
          spellCheck={false}
          value={value}
          onChange={(e) => onChange(a.name, e.target.value)}
        />
      )}
      {a.help && <FieldDescription>{a.help}</FieldDescription>}
    </Field>
  )
}

function SubjectStep({
  data,
  state,
  setState,
}: StepProps & { data: EditorData }) {
  const p = presetOf(data.presets, state.preset)
  const { identity, errors } = build(data.presets, state)
  const formats = [...new Set([state.nameIdFormat, ...data.nameIdFormats])]
  const formatItems = formats.map((f) => ({ label: short(f), value: f }))
  const source = nameIdSource(data.presets, state)
  const customErrors = errors
    .filter((e) => e.startsWith("Custom attributes:"))
    .map((e) => e.replace("Custom attributes: ", ""))
  const followText = identity.name_id
    ? source
      ? `follows ${p.attributes.find((a) => a.name === source)?.label ?? short(source)}`
      : "template default"
    : "generated by localsaml"
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        The subject NameID, and any extra attributes. Persistent and transient
        NameIDs are generated unless you type one.
      </p>
      <FieldGroup className="grid gap-4 sm:grid-cols-2">
        <Field>
          <FieldLabel>NameID format</FieldLabel>
          <Select
            items={formatItems}
            value={state.nameIdFormat}
            onValueChange={(v) =>
              v &&
              setState((s) => ({ ...s, nameIdFormat: v, nameIdAuto: true }))
            }
          >
            <SelectTrigger className="w-full" aria-label="NameID format">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {formatItems.map((f) => (
                <SelectItem key={f.value} value={f.value}>
                  {f.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {data.requestedNameIdFormat && (
            <FieldDescription>
              The service provider asked for {short(data.requestedNameIdFormat)}
              .
            </FieldDescription>
          )}
        </Field>
        <Field>
          <FieldLabel htmlFor="name-id">NameID</FieldLabel>
          <Input
            id="name-id"
            spellCheck={false}
            className="font-mono"
            placeholder={
              state.nameIdFormat === NAME_ID.TRANSIENT
                ? "generated: new each session"
                : state.nameIdFormat === NAME_ID.PERSISTENT
                  ? "generated: stable per service provider"
                  : ""
            }
            value={state.nameIdAuto ? identity.name_id : state.nameId}
            onChange={(e) =>
              setState((s) => ({
                ...s,
                nameId: e.target.value,
                nameIdAuto: false,
              }))
            }
          />
          <FieldDescription>
            {state.nameIdAuto ? (
              followText
            ) : (
              <Button
                variant="link"
                size="xs"
                className="h-auto px-0"
                onClick={() => setState((s) => ({ ...s, nameIdAuto: true }))}
              >
                <RotateCcwIcon data-icon="inline-start" />
                Follow the template
              </Button>
            )}
          </FieldDescription>
        </Field>
        <Field
          className="sm:col-span-2"
          data-invalid={customErrors.length > 0 || undefined}
        >
          <FieldLabel htmlFor="custom-attributes">Custom attributes</FieldLabel>
          <Textarea
            id="custom-attributes"
            rows={6}
            spellCheck={false}
            className="font-mono text-xs"
            aria-invalid={customErrors.length > 0 || undefined}
            placeholder={
              '{\n  "department": "Engineering",\n  "memberOf": ["admins", "developers"],\n  "firstName": null\n}'
            }
            value={state.custom}
            onChange={(e) =>
              setState((s) => ({ ...s, custom: e.target.value }))
            }
          />
          <FieldDescription>
            JSON: strings or lists of strings; null removes one.
          </FieldDescription>
          {customErrors.length > 0 && (
            <FieldError>{customErrors.join(" · ")}</FieldError>
          )}
        </Field>
      </FieldGroup>
      <XmlBlock
        title={
          <>
            Preview{" "}
            <span className="font-normal text-muted-foreground">
              (the Issuer, Conditions, AuthnStatement and signatures are added
              by the server)
            </span>
          </>
        }
        xml={previewXml(data.presets, state, identity)}
      />
    </div>
  )
}

/** "Save identity", beside the page's Sign in or Generate button so it's there at every step. */
export function SaveIdentity({
  data,
  state,
}: {
  data: EditorData
  state: EditorState
}) {
  const [name, setName] = React.useState<string | null>(null)
  const [saved, setSaved] = React.useState(false)
  const { identity, errors } = build(data.presets, state)
  const suggested = describe(data.presets, { preset: state.preset, identity })

  React.useEffect(() => {
    if (!saved) return
    const timer = setTimeout(() => setSaved(false), 1400)
    return () => clearTimeout(timer)
  }, [saved])

  return (
    <div className="flex items-center gap-2">
      <Input
        aria-label="Name for the saved identity"
        placeholder="Name"
        className="w-44"
        value={name ?? suggested}
        onChange={(e) => setName(e.target.value)}
      />
      <Button
        type="button"
        variant="outline"
        disabled={errors.length > 0}
        onClick={() => {
          saveIdentity({
            name: (name ?? suggested).trim() || suggested,
            ...storedEntry(state, identity),
          })
          setSaved(true)
        }}
      >
        {saved ? (
          <CheckIcon data-icon="inline-start" />
        ) : (
          <SaveIcon data-icon="inline-start" />
        )}
        {saved ? "Saved" : "Save identity"}
      </Button>
    </div>
  )
}
