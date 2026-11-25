import { LogInIcon, LogOutIcon, SearchIcon } from "lucide-react"
import { useLoaderData } from "react-router"

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
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { api } from "@/lib/api"
import { short } from "@/lib/identity"
import { useInfo } from "@/lib/root"
import type { TestSp } from "@/lib/types"

export const testSpLoader = () => api<TestSp>("/dev/api/test-sp")

/** A select that submits with its form. */
function FormSelect({
  name,
  label,
  items,
  defaultValue,
}: {
  name: string
  label: string
  items: { label: string; value: string }[]
  defaultValue: string
}) {
  return (
    <Field>
      <FieldLabel>{label}</FieldLabel>
      <Select name={name} items={items} defaultValue={defaultValue}>
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

const choices = (values: string[]) => [
  { label: "(none)", value: "" },
  ...values.map((v) => ({ label: short(v), value: v })),
]

/**
 * The built-in service provider: it starts logins, validates the Responses like a strict SP
 * would, and can log out and query attributes. Its forms go to its own endpoints.
 */
export function TestSpPage() {
  const info = useInfo()
  const sp = useLoaderData<TestSp>()
  const session = sp.session
  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription>Built-in service provider</CardDescription>
          <CardTitle className="text-xl">
            Test SP for{" "}
            <span className="font-mono text-primary">{info.entity_id}</span>
          </CardTitle>
          <CardDescription>
            Try logins without an app. This service provider validates the
            Response the way a strict one would (signatures, decryption,
            audience, recipient, timestamps against real time, InResponseTo,
            replays) and shows what it found. Its entity ID is{" "}
            <code>{sp.entity_id}</code>; its{" "}
            <a href={sp.metadata} className="underline underline-offset-4">
              metadata
            </a>{" "}
            declares the ACS <code>{sp.acs}</code>.
          </CardDescription>
        </CardHeader>
      </Card>
      {session && (
        <Card>
          <CardHeader>
            <CardDescription>Signed in</CardDescription>
            <CardTitle>
              As{" "}
              <span className="font-mono text-primary">{session.name_id}</span>
            </CardTitle>
            <CardDescription className="flex flex-wrap gap-2">
              <Badge variant="secondary">{short(session.format)}</Badge>
              {session.session_index && (
                <Badge variant="outline" className="font-mono">
                  SessionIndex {session.session_index}
                </Badge>
              )}
            </CardDescription>
          </CardHeader>
          <CardFooter className="gap-2 border-t">
            <form method="post" action={sp.logout}>
              <Button type="submit" variant="outline">
                <LogOutIcon data-icon="inline-start" />
                Sign out (SP-initiated logout)
              </Button>
            </form>
            <form method="post" action={sp.attributes}>
              <Button type="submit" variant="ghost">
                <SearchIcon data-icon="inline-start" />
                Query attributes (AttributeQuery)
              </Button>
            </form>
          </CardFooter>
        </Card>
      )}
      <form method="get" action={sp.login}>
        <Card>
          <CardHeader>
            <CardTitle>SP-initiated login</CardTitle>
          </CardHeader>
          <CardContent>
            <FieldGroup className="grid gap-4 sm:grid-cols-2">
              <FormSelect
                name="binding"
                label="Binding"
                defaultValue="redirect"
                items={[
                  { label: "HTTP-Redirect", value: "redirect" },
                  { label: "HTTP-POST", value: "post" },
                ]}
              />
              <FormSelect
                name="response_binding"
                label="Response binding"
                defaultValue="post"
                items={[
                  { label: "HTTP-POST", value: "post" },
                  { label: "HTTP-Artifact", value: "artifact" },
                ]}
              />
              <FormSelect
                name="name_id_format"
                label="NameIDPolicy format"
                defaultValue=""
                items={choices(sp.name_id_formats)}
              />
              <FormSelect
                name="authn_context"
                label="Requested AuthnContext"
                defaultValue=""
                items={choices(sp.authn_contexts)}
              />
              <Field>
                <FieldLabel htmlFor="sp-relay">RelayState</FieldLabel>
                <Input
                  id="sp-relay"
                  name="RelayState"
                  defaultValue="/welcome"
                />
              </Field>
              <div className="grid grid-cols-2 content-end gap-3">
                {[
                  ["sign", "Sign the request", true],
                  ["force_authn", "ForceAuthn", false],
                  ["is_passive", "IsPassive", false],
                  ["encrypt_name_id", "Encrypted NameID", false],
                ].map(([name, label, checked]) => (
                  <Field key={String(name)} orientation="horizontal">
                    <Checkbox
                      id={`sp-${String(name)}`}
                      name={String(name)}
                      value="1"
                      defaultChecked={checked === true}
                    />
                    <FieldLabel htmlFor={`sp-${String(name)}`}>
                      {label}
                    </FieldLabel>
                  </Field>
                ))}
              </div>
            </FieldGroup>
          </CardContent>
          <CardFooter className="gap-2 border-t">
            <Button type="submit">
              <LogInIcon data-icon="inline-start" />
              Start login
            </Button>
            <a
              href={sp.initiate}
              className={buttonVariants({ variant: "ghost" })}
            >
              IdP-initiated login instead
            </a>
          </CardFooter>
        </Card>
      </form>
    </div>
  )
}
