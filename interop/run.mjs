#!/usr/bin/env node
// Interop harness: drives a real localsaml binary with real SAML service-provider libraries
// (@node-saml/node-saml and samlify) against every identity provider template, and checks the
// libraries accept good Responses and reject deliberately broken ones.
//
//   node run.mjs                 # build, start localsaml on :9411, run everything
//   node run.mjs --only okta     # one template (root, generic, entra, okta, ...)
//   node run.mjs --no-build      # use the existing target/debug/localsaml
//   node run.mjs --binary PATH   # use another binary (e.g. target/release/localsaml)
//   node run.mjs --verbose       # print failure details as they happen

import { execFileSync, spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SAML } from '@node-saml/node-saml';
import * as samlify from 'samlify';
import * as xmllint from '@authenio/samlify-node-xmllint';

samlify.setSchemaValidator(xmllint);
// The xmllint WebAssembly module adds listeners per validation.
EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..');
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const ONLY = option('--only');
const VERBOSE = flag('--verbose');
const PORT = Number(option('--port') || 9411);
const BASE = `http://localhost:${PORT}`;

const EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const SP_HOST = 'http://sp.interop.test';

// ---------------------------------------------------------------- results

const results = [];
async function check(issuer, lib, name, fn) {
  try {
    const detail = await fn();
    results.push({ issuer, lib, name, ok: true, detail: detail || '' });
  } catch (err) {
    const detail = (err && err.message) || String(err);
    results.push({ issuer, lib, name, ok: false, detail });
    if (VERBOSE) console.error(`FAIL ${issuer} ${lib} ${name}: ${(err && err.stack) || detail}`);
  }
}
function assert(cond, message) {
  if (!cond) throw new Error(message);
}
/** Expect `fn` to throw (a library rejecting a broken Response). */
async function rejects(fn) {
  try {
    await fn();
  } catch (err) {
    return `rejected: ${(err && err.message) || err}`.slice(0, 120);
  }
  throw new Error('accepted a Response it should have rejected');
}

// ---------------------------------------------------------------- server

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'localsaml-interop-'));

function spKeys() {
  const key = path.join(tmp, 'sp.key');
  const cert = path.join(tmp, 'sp.crt');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '7',
    '-subj', '/CN=localsaml-interop-sp', '-keyout', key, '-out', cert], { stdio: 'ignore' });
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(cert, 'utf8') };
}

/** The SPs the harness plays, declared in localsaml.toml (certificate, ACS and SLO URLs). */
function declaredSps(keys) {
  const entries = [];
  const add = (name, extra = '') => {
    const sp = spEntity(name);
    entries.push(`[[service_providers]]
entity_id = "${sp.entityId}"
acs_urls = ["${sp.acs}"]
slo_url = "${sp.slo}"
certificate = """
${keys.cert.trim()}
"""
${extra}`);
  };
  add('node-saml');
  add('samlify');
  for (const alg of ['aes256-gcm', 'aes128-cbc']) {
    for (const lib of ['node-saml', 'samlify']) add(`enc-${alg}-${lib}`, `encrypt_assertions = true\nencryption_algorithm = "${alg}"`);
  }
  return entries.join('\n');
}

async function startServer(keys) {
  let binary = option('--binary');
  if (!binary) {
    if (!flag('--no-build')) {
      console.log('building localsaml…');
      execFileSync('cargo', ['build', '--quiet'], { cwd: repo, stdio: 'inherit' });
    }
    binary = path.join(repo, 'target', 'debug', 'localsaml');
  }
  // A declared user, for dev_user. Run from the temp dir so no other localsaml.toml is picked up.
  fs.writeFileSync(path.join(tmp, 'localsaml.toml'), `
[[users]]
id = "alice"
label = "Alice (interop)"
name_id = "alice@example.com"
name_id_format = "${EMAIL}"
attributes = { department = "QA", interopRoles = ["admin", "auditor"] }

${declaredSps(keys)}
`);
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('LOCALSAML_')));
  const child = spawn(path.resolve(binary), [
    '--ephemeral-keys', '--port', String(PORT), '--base-url', BASE, '--data-dir', path.join(tmp, 'data'),
  ], { cwd: tmp, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  child.stdout.on('data', (d) => (log += d));
  child.stderr.on('data', (d) => (log += d));
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`localsaml exited early:\n${log}`);
    try {
      if ((await fetch(`${BASE}/health`)).ok) return { child, log: () => log };
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill();
  throw new Error(`localsaml didn't start on ${BASE}:\n${log}`);
}

// ---------------------------------------------------------------- HTTP

/** A cookie jar per simulated browser. */
class Browser {
  constructor() { this.cookies = new Map(); }
  async fetch(url, init = {}) {
    const headers = { ...(init.headers || {}) };
    if (this.cookies.size) headers.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(';');
      const [k, v] = [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)];
      if (attrs.some((a) => /max-age=0/i.test(a.trim()))) this.cookies.delete(k.trim()); else this.cookies.set(k.trim(), v);
    }
    return res;
  }
  async get(url) { return this.fetch(url); }
  async post(url, form) {
    return this.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
    });
  }
}

const unescapeHtml = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const input = (html, name) => {
  const m = html.match(new RegExp(`name="${name}" value="([^"]*)"`));
  return m ? unescapeHtml(m[1]) : undefined;
};
const title = (html) => (html.match(/<title>([^<]*)/) || [])[1] || '';
const errorText = (html) => {
  const m = html.match(/<h1>([^<]*)<\/h1><p>([^<]*)/);
  return m ? `${unescapeHtml(m[1])}: ${unescapeHtml(m[2])}` : title(html);
};

/** The HTTP-POST binding page: where it posts, and what. */
async function postedMessage(res) {
  const html = await res.text();
  const action = (html.match(/<form method="post" action="([^"]*)"/) || [])[1];
  const SAMLResponse = input(html, 'SAMLResponse');
  if (!action || !SAMLResponse) throw new Error(`expected an auto-posted SAMLResponse, got ${res.status} "${errorText(html)}"`);
  const RelayState = input(html, 'RelayState');
  return { action: unescapeHtml(action), SAMLResponse, ...(RelayState !== undefined ? { RelayState } : {}) };
}

/** Complete a login started at `res` (the redirect or POST to the SSO URL) through the login form. */
async function viaLoginForm(browser, res, preset, identity) {
  const html = await res.text();
  const req = input(html, 'req');
  if (!req) throw new Error(`expected the login page, got ${res.status} "${errorText(html)}"`);
  const action = (html.match(/id="lo-form"|action="([^"]*)" id="lo-form"/) && html.match(/action="([^"]*)" id="lo-form"/)[1]) || '/login';
  return browser.post(new URL(unescapeHtml(action), BASE).href, {
    req, action: 'approve', preset, identity: JSON.stringify(identity),
  });
}

// ---------------------------------------------------------------- localsaml facts

async function json(url, init) {
  const res = await fetch(url, init);
  const body = await res.json();
  if (!res.ok) throw new Error(`${url}: ${res.status} ${JSON.stringify(body)}`);
  return body;
}

async function metadataOf(base) {
  const xml = await (await fetch(`${base}/metadata`)).text();
  const certs = [...xml.matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map((m) => m[1]);
  const location = (kind, binding) => (xml.match(new RegExp(`<md:${kind} Binding="urn:oasis:names:tc:SAML:2.0:bindings:${binding}" Location="([^"]+)"`)) || [])[1];
  return {
    xml,
    entityId: xml.match(/entityID="([^"]+)"/)[1],
    certs: certs.map(pem),
    sso: location('SingleSignOnService', 'HTTP-Redirect'),
    ssoPost: location('SingleSignOnService', 'HTTP-POST'),
    slo: location('SingleLogoutService', 'HTTP-Redirect'),
  };
}

const pem = (b64) => `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

async function registerSp(sp) {
  return json(`${BASE}/dev/api/service-providers`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(sp),
  });
}

// ---------------------------------------------------------------- service providers

function spEntity(name) {
  return { entityId: `${SP_HOST}/${name}`, acs: `${SP_HOST}/${name}/acs`, slo: `${SP_HOST}/${name}/slo` };
}

/** A node-saml SP for an issuer. */
function nodeSaml(issuer, sp, keys, extra = {}) {
  return new SAML({
    entryPoint: issuer.md.sso,
    logoutUrl: issuer.md.slo,
    idpCert: issuer.md.certs,
    idpIssuer: issuer.md.entityId,
    issuer: sp.entityId,
    callbackUrl: sp.acs,
    logoutCallbackUrl: sp.slo,
    audience: sp.entityId,
    privateKey: keys.key,
    publicCert: keys.cert,
    decryptionPvk: keys.key,
    signatureAlgorithm: 'sha256',
    wantAuthnResponseSigned: issuer.preset.sign_response,
    wantAssertionsSigned: issuer.preset.sign_assertion,
    validateInResponseTo: 'always',
    acceptedClockSkewMs: 5000,
    ...extra,
  });
}

/** A samlify IdP + SP pair for an issuer. */
function samlifyPair(issuer, sp, keys, { signed = true, encrypted = issuer.preset.encrypt_when_possible, metadata = issuer.md.xml, sha256Only = false } = {}) {
  // samlify refuses to sign AuthnRequests unless the IdP metadata says WantAuthnRequestsSigned="true"
  // (it requires the two flags to agree). localsaml verifies signed requests whatever its metadata
  // says, so present it as an IdP that wants them.
  if (signed) metadata = metadata.replace('WantAuthnRequestsSigned="false"', 'WantAuthnRequestsSigned="true"');
  const idp = samlify.IdentityProvider({ metadata, isAssertionEncrypted: encrypted });
  const s = samlify.ServiceProvider({
    entityID: sp.entityId,
    authnRequestsSigned: signed,
    wantAssertionsSigned: issuer.preset.sign_assertion,
    wantMessageSigned: issuer.preset.sign_response,
    wantLogoutResponseSigned: true,
    wantLogoutRequestSigned: true,
    // samlify falls back to a Response/Issuer signature location for every message it signs,
    // which doesn't exist in an AuthnRequest (POST binding).
    signatureConfig: { prefix: 'ds', location: { reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']", action: 'after' } },
    ...(sha256Only ? { allowedSignatureAlgorithms: ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'] } : {}),
    privateKey: keys.key,
    signingCert: keys.cert,
    encPrivateKey: keys.key,
    encryptCert: keys.cert,
    requestSignatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    assertionConsumerService: [{ Binding: samlify.Constants.namespace.binding.post, Location: sp.acs }],
    singleLogoutService: [{ Binding: samlify.Constants.namespace.binding.redirect, Location: sp.slo }],
    clockDrifts: [-5000, 5000],
  });
  return { idp, sp: s };
}

/** Split a redirect URL into what samlify's redirect flow wants: the decoded query (as a web
 * framework parses it) and the raw octet string that was signed. */
function redirectParts(location) {
  const query = location.slice(location.indexOf('?') + 1);
  const rawPairs = Object.fromEntries(query.split('&').map((p) => [p.slice(0, p.indexOf('=')), p.slice(p.indexOf('=') + 1)]));
  const raw = Object.fromEntries(new URLSearchParams(query));
  const msg0 = raw.SAMLRequest !== undefined ? 'SAMLRequest' : 'SAMLResponse';
  const octetString = [`${msg0}=${rawPairs[msg0]}`, rawPairs.RelayState !== undefined ? `RelayState=${rawPairs.RelayState}` : null, `SigAlg=${rawPairs.SigAlg}`].filter(Boolean).join('&');
  return { raw, query, octetString };
}


// ---------------------------------------------------------------- scenarios

async function runIssuer(issuer, keys) {
  const name = issuer.id;
  const p = issuer.preset;
  const emailAttr = p.email_attribute;
  const expectEmail = (tag) => `${tag}-${name}@example.com`;
  /** Attributes that make the NameID (requested as emailAddress) predictable. */
  const attrsFor = (email) => {
    const a = { [emailAttr]: email };
    if (p.name_id_from) a[p.name_id_from] = email;
    return a;
  };
  const checkAttr = (attributes, value) => {
    const got = attributes[emailAttr];
    const v = Array.isArray(got) ? got[0] : got;
    assert(v === value, `attribute ${emailAttr} is ${JSON.stringify(got)}, expected ${value}`);
  };

  const nsp = spEntity('node-saml');
  const ssp = spEntity('samlify');

  // node-saml, Redirect binding, signed request, finished with dev_attributes.
  await check(name, 'node-saml', 'SP-initiated, Redirect, signed, dev_attributes', async () => {
    const saml = nodeSaml(issuer, nsp, keys);
    const url = await saml.getAuthorizeUrlAsync('rs-1', {});
    const email = expectEmail('ns');
    const b = new Browser();
    const res = await b.get(`${url}&dev_attributes=${encodeURIComponent(JSON.stringify(attrsFor(email)))}`);
    const posted = await postedMessage(res);
    assert(posted.action === nsp.acs, `posted to ${posted.action}`);
    assert(posted.RelayState === 'rs-1', `RelayState ${posted.RelayState}`);
    const { profile } = await saml.validatePostResponseAsync(posted);
    assert(profile.nameID === email, `NameID ${profile.nameID}, expected ${email}`);
    assert(profile.nameIDFormat === EMAIL, `NameID format ${profile.nameIDFormat}`);
    checkAttr(profile.attributes || profile, email);
    return `NameID ${profile.nameID}`;
  });

  // node-saml, Redirect binding, unsigned request, finished through the login form.
  await check(name, 'node-saml', 'SP-initiated, Redirect, unsigned, login form', async () => {
    const saml = nodeSaml(issuer, nsp, keys, { privateKey: undefined });
    const url = await saml.getAuthorizeUrlAsync('', {});
    const b = new Browser();
    const email = expectEmail('form');
    const res = await viaLoginForm(b, await b.get(url), p.id, { name_id: email, name_id_format: EMAIL, attributes: { [emailAttr]: email, extraList: ['x', 'y'] } });
    const { profile } = await saml.validatePostResponseAsync(await postedMessage(res));
    assert(profile.nameID === email, `NameID ${profile.nameID}`);
    const extra = profile.attributes.extraList;
    assert(Array.isArray(extra) && extra.join() === 'x,y', `extraList ${JSON.stringify(extra)}`);
    return `NameID ${profile.nameID}`;
  });

  // samlify, Redirect binding, signed request, dev_user.
  await check(name, 'samlify', 'SP-initiated, Redirect, signed, dev_user', async () => {
    const { idp, sp } = samlifyPair(issuer, ssp, keys);
    const { id, context } = sp.createLoginRequest(idp, 'redirect');
    const b = new Browser();
    const res = await b.get(`${context}&dev_user=alice`);
    const posted = await postedMessage(res);
    const { extract } = await sp.parseLoginResponse(idp, 'post', { body: posted }, { inResponseTo: id });
    assert(extract.nameID === 'alice@example.com', `NameID ${extract.nameID}`);
    assert(extract.attributes.department === 'QA', `department ${JSON.stringify(extract.attributes.department)}`);
    return `NameID ${extract.nameID}`;
  });

  // samlify, POST binding, signed request (enveloped signature), dev_attributes in the form.
  await check(name, 'samlify', 'SP-initiated, POST, signed, dev_attributes', async () => {
    const { idp, sp } = samlifyPair(issuer, ssp, keys);
    const req = sp.createLoginRequest(idp, 'post');
    const email = expectEmail('sfpost');
    const b = new Browser();
    const res = await b.post(req.entityEndpoint, {
      SAMLRequest: req.context, RelayState: 'rs-post', dev_attributes: JSON.stringify(attrsFor(email)),
    });
    const posted = await postedMessage(res);
    assert(posted.RelayState === 'rs-post', `RelayState ${posted.RelayState}`);
    const { extract } = await sp.parseLoginResponse(idp, 'post', { body: posted }, { inResponseTo: req.id });
    const got = extract.attributes[emailAttr];
    assert((Array.isArray(got) ? got[0] : got) === email, `attribute ${emailAttr} ${JSON.stringify(got)}`);
    return `NameID ${extract.nameID}`;
  });

  // samlify, POST binding, unsigned request, login form.
  await check(name, 'samlify', 'SP-initiated, POST, unsigned, login form', async () => {
    const { idp, sp } = samlifyPair(issuer, ssp, keys, { signed: false });
    const req = sp.createLoginRequest(idp, 'post');
    const b = new Browser();
    const email = expectEmail('sfform');
    const res = await viaLoginForm(b, await b.post(req.entityEndpoint, { SAMLRequest: req.context }), p.id, {
      name_id: email, name_id_format: EMAIL, attributes: { [emailAttr]: email },
    });
    const { extract } = await sp.parseLoginResponse(idp, 'post', { body: await postedMessage(res) }, { inResponseTo: req.id });
    assert(extract.nameID === email, `NameID ${extract.nameID}`);
    return `NameID ${extract.nameID}`;
  });

  // Encrypted assertions, for SPs registered with encrypt_assertions.
  for (const [alg, lib] of [['aes256-gcm', 'node-saml'], ['aes128-cbc', 'node-saml'], ['aes256-gcm', 'samlify'], ['aes128-cbc', 'samlify']]) {
    await check(name, lib, `encrypted assertion (${alg})`, async () => {
      const sp = spEntity(`enc-${alg}-${lib}`);
      const email = expectEmail('enc');
      if (lib === 'node-saml') {
        const saml = nodeSaml(issuer, sp, keys);
        const url = await saml.getAuthorizeUrlAsync('', {});
        const posted = await postedMessage(await new Browser().get(`${url}&dev_attributes=${encodeURIComponent(JSON.stringify(attrsFor(email)))}`));
        assert(Buffer.from(posted.SAMLResponse, 'base64').toString().includes('EncryptedAssertion'), 'the assertion is not encrypted');
        const { profile } = await saml.validatePostResponseAsync(posted);
        assert(profile.nameID === email, `NameID ${profile.nameID}`);
        return `NameID ${profile.nameID}`;
      }
      const { idp, sp: s } = samlifyPair(issuer, sp, keys, { encrypted: true });
      const { id, context } = s.createLoginRequest(idp, 'redirect');
      const posted = await postedMessage(await new Browser().get(`${context}&dev_attributes=${encodeURIComponent(JSON.stringify(attrsFor(email)))}`));
      assert(Buffer.from(posted.SAMLResponse, 'base64').toString().includes('EncryptedAssertion'), 'the assertion is not encrypted');
      const { extract } = await s.parseLoginResponse(idp, 'post', { body: posted }, { inResponseTo: id });
      return `NameID ${extract.nameID}`;
    });
  }

  // IdP-initiated SSO.
  await check(name, 'node-saml', 'IdP-initiated (/sso/initiate)', async () => {
    const saml = nodeSaml(issuer, nsp, keys, { validateInResponseTo: 'ifPresent' });
    const email = expectEmail('idpinit');
    const res = await new Browser().get(`${issuer.base}/sso/initiate?sp=${encodeURIComponent(nsp.entityId)}&RelayState=%2Fhome&dev_attributes=${encodeURIComponent(JSON.stringify(attrsFor(email)))}`);
    const posted = await postedMessage(res);
    assert(posted.RelayState === '/home', `RelayState ${posted.RelayState}`);
    const xml = Buffer.from(posted.SAMLResponse, 'base64').toString();
    assert(!/InResponseTo=/.test(xml), 'an unsolicited Response has InResponseTo');
    const { profile } = await saml.validatePostResponseAsync(posted);
    return `NameID ${profile.nameID}`;
  });
  await check(name, 'samlify', 'IdP-initiated (/sso/initiate)', async () => {
    const { idp, sp } = samlifyPair(issuer, ssp, keys);
    const posted = await postedMessage(await new Browser().get(`${issuer.base}/sso/initiate?sp=${encodeURIComponent(ssp.entityId)}&dev_user=alice`));
    const { extract } = await sp.parseLoginResponse(idp, 'post', { body: posted });
    assert(extract.nameID === 'alice@example.com', `NameID ${extract.nameID}`);
    return `NameID ${extract.nameID}`;
  });

  // Single logout.
  if (!p.single_logout) {
    await check(name, 'node-saml', 'SLO is refused (template has none)', async () => {
      assert(!issuer.md.slo, 'metadata advertises an SLO endpoint');
      return 'no SingleLogoutService in metadata';
    });
  } else {
    await check(name, 'node-saml', 'SP-initiated SLO (Redirect)', async () => {
      const saml = nodeSaml(issuer, nsp, keys);
      const b = new Browser();
      const url = await saml.getAuthorizeUrlAsync('', {});
      const { profile } = await saml.validatePostResponseAsync(await postedMessage(await b.get(`${url}&dev_user=alice`)));
      const logoutUrl = await saml.getLogoutUrlAsync(profile, 'bye', {});
      const res = await b.get(logoutUrl);
      const location = res.headers.get('location');
      assert(location && location.startsWith(nsp.slo), `expected a redirect to ${nsp.slo}, got ${res.status} ${location || errorText(await res.text())}`);
      const query = location.slice(location.indexOf('?') + 1);
      const { loggedOut } = await saml.validateRedirectAsync(Object.fromEntries(new URLSearchParams(query)), query);
      assert(loggedOut, 'not logged out');
      assert(![...b.cookies.keys()].some((k) => k.startsWith('localsaml_sid_')), 'the IdP session cookie is still set');
      return 'LogoutResponse verified';
    });
    await check(name, 'samlify', 'SP-initiated SLO, propagated to a second SP', async () => {
      // node-saml and samlify SPs share one browser session; node-saml logs out, so localsaml must
      // log samlify out (LogoutRequest → LogoutResponse) before answering node-saml.
      const saml = nodeSaml(issuer, nsp, keys);
      const { idp, sp } = samlifyPair(issuer, ssp, keys);
      const b = new Browser();
      const url = await saml.getAuthorizeUrlAsync('', {});
      const { profile } = await saml.validatePostResponseAsync(await postedMessage(await b.get(`${url}&dev_user=alice`)));
      const req = sp.createLoginRequest(idp, 'redirect');
      await sp.parseLoginResponse(idp, 'post', { body: await postedMessage(await b.get(`${req.context}&dev_user=alice`)) }, { inResponseTo: req.id });
      let res = await b.get(await saml.getLogoutUrlAsync(profile, '', {}));
      let location = res.headers.get('location');
      assert(location && location.startsWith(ssp.slo), `expected a LogoutRequest to ${ssp.slo}, got ${res.status} ${location || errorText(await res.text())}`);
      const parts = redirectParts(location);
      const parsed = await sp.parseLogoutRequest(idp, 'redirect', { query: parts.raw, octetString: parts.octetString });
      assert(parsed.extract.nameID === 'alice@example.com', `LogoutRequest NameID ${parsed.extract.nameID}`);
      const answer = sp.createLogoutResponse(idp, parsed, 'redirect', parts.raw.RelayState || '');
      res = await b.get(answer.context);
      location = res.headers.get('location');
      assert(location && location.startsWith(nsp.slo), `expected the LogoutResponse to ${nsp.slo}, got ${res.status} ${location || errorText(await res.text())}`);
      const query = location.slice(location.indexOf('?') + 1);
      const { loggedOut } = await saml.validateRedirectAsync(Object.fromEntries(new URLSearchParams(query)), query);
      assert(loggedOut, 'not logged out');
      const status = (Buffer.from(new URLSearchParams(query).get('SAMLResponse'), 'base64'));
      return 'samlify logged out, node-saml got its LogoutResponse';
    });
    await check(name, 'samlify', 'SP-initiated SLO (samlify parses the LogoutResponse)', async () => {
      const { idp, sp } = samlifyPair(issuer, ssp, keys);
      const b = new Browser();
      const req = sp.createLoginRequest(idp, 'redirect');
      const { extract } = await sp.parseLoginResponse(idp, 'post', { body: await postedMessage(await b.get(`${req.context}&dev_user=alice`)) }, { inResponseTo: req.id });
      const logout = sp.createLogoutRequest(idp, 'redirect', { logoutNameID: extract.nameID, sessionIndex: extract.sessionIndex && extract.sessionIndex.sessionIndex });
      const res = await b.get(logout.context);
      const location = res.headers.get('location');
      assert(location && location.startsWith(ssp.slo), `expected a redirect to ${ssp.slo}, got ${res.status} ${location || errorText(await res.text())}`);
      const parts = redirectParts(location);
      const parsed = await sp.parseLogoutResponse(idp, 'redirect', { query: parts.raw, octetString: parts.octetString });
      assert(parsed.extract.response.inResponseTo === logout.id, `InResponseTo ${parsed.extract.response.inResponseTo}`);
      return 'LogoutResponse verified';
    });
  }

  // Deliberately broken Responses must be rejected; an untouched one must be accepted.
  const mint = async (sp, query = '') => {
    const r = await json(`${issuer.base}/dev/api/response?sp=${encodeURIComponent(sp.entityId)}&${attrQuery(emailAttr, expectEmail('mint'))}${query}`);
    return { SAMLResponse: r.saml_response };
  };
  for (const lib of ['node-saml', 'samlify']) {
    const sp = lib === 'node-saml' ? nsp : ssp;
    const validate = async (posted, sha256Only = false) => {
      if (lib === 'node-saml') {
        return nodeSaml(issuer, sp, keys, { validateInResponseTo: 'ifPresent' }).validatePostResponseAsync(posted);
      }
      const { idp, sp: s } = samlifyPair(issuer, sp, keys, { sha256Only });
      return s.parseLoginResponse(idp, 'post', { body: posted });
    };
    await check(name, lib, 'minted Response accepted (control)', async () => {
      await validate(await mint(sp));
      return 'accepted';
    });
    // node-saml 5 only logs a wrong Recipient or Destination (it plans to reject them in its next
    // major version), so those checks run against samlify only.
    // RSA-SHA1 is accepted by both libraries by default; samlify can be told not to.
    const tampers = ['bad_signature', 'wrong_cert', 'wrong_audience', 'wrong_issuer', 'expired', 'not_yet_valid', 'unsigned'];
    if (lib === 'samlify') tampers.push('wrong_recipient', 'wrong_destination', 'sha1');
    for (const tamper of tampers) {
      await check(name, lib, `tamper=${tamper} rejected`, async () => rejects(async () => validate(await mint(sp, `&tamper=${tamper}`), tamper === 'sha1')));
    }
    await check(name, lib, 'error status (AuthnFailed) rejected', async () => rejects(async () => validate(await mint(sp, '&status=AuthnFailed'))));
  }
  return { mint, nsp };
}

function attrQuery(name, value) {
  return `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
}

/** Key rotation: Responses issued before and after verify against the new metadata. */
async function rotation(issuers, keys) {
  const issuer = issuers.find((i) => i.id === 'root') || issuers[0];
  const sp = spEntity('node-saml');
  const mint = async () => ({ SAMLResponse: (await json(`${issuer.base}/dev/api/response?sp=${encodeURIComponent(sp.entityId)}`)).saml_response });
  const before = await mint();
  const oldMd = issuer.md;
  await json(`${BASE}/dev/api/rotate-keys`, { method: 'POST' });
  const newMd = await metadataOf(issuer.base);
  const after = await mint();
  const saml = (md) => nodeSaml({ ...issuer, md }, sp, keys, { validateInResponseTo: 'never' });
  await check(issuer.id, 'node-saml', 'rotation: new metadata lists both certificates', async () => {
    assert(newMd.certs.length === oldMd.certs.length + 1, `${newMd.certs.length} certificates`);
    assert(newMd.certs[1] === oldMd.certs[0], 'the old certificate is not second');
    return `${newMd.certs.length} certificates`;
  });
  await check(issuer.id, 'node-saml', 'rotation: pre-rotation Response verifies with new metadata', async () => {
    await saml(newMd).validatePostResponseAsync(before);
    return 'accepted';
  });
  await check(issuer.id, 'node-saml', 'rotation: post-rotation Response verifies with new metadata', async () => {
    await saml(newMd).validatePostResponseAsync(after);
    return 'accepted';
  });
  await check(issuer.id, 'node-saml', 'rotation: post-rotation Response rejected by a pinned old cert', async () =>
    rejects(() => saml(oldMd).validatePostResponseAsync(after)));
  await check(issuer.id, 'samlify', 'rotation: post-rotation Response verifies with new metadata', async () => {
    const { idp, sp: s } = samlifyPair(issuer, spEntity('samlify'), keys, { metadata: newMd.xml });
    const r = { SAMLResponse: (await json(`${issuer.base}/dev/api/response?sp=${encodeURIComponent(`${SP_HOST}/samlify`)}`)).saml_response };
    await s.parseLoginResponse(idp, 'post', { body: r });
    return 'accepted';
  });
}

// ---------------------------------------------------------------- main

async function main() {
  const keys = spKeys();
  const server = await startServer(keys);
  let failed = false;
  try {
    const presets = await json(`${BASE}/dev/api/presets`);
    const byId = Object.fromEntries(presets.map((p) => [p.id, p]));
    let issuers = [{ id: 'root', base: BASE, preset: byId.generic }, ...presets.map((p) => ({ id: p.id, base: `${BASE}/p/${p.id}`, preset: p }))];
    if (ONLY) issuers = issuers.filter((i) => i.id === ONLY);
    if (!issuers.length) throw new Error(`no template '${ONLY}'`);
    for (const issuer of issuers) issuer.md = await metadataOf(issuer.base);

    // The harness's SPs are declared in localsaml.toml; check registering one over the API too.
    await check('root', 'api', 'register an SP over /dev/api/service-providers', async () => {
      const sp = spEntity('api-registered');
      await registerSp({ entity_id: sp.entityId, acs_urls: [sp.acs], slo_url: sp.slo, certificate: keys.cert, encrypt_assertions: true });
      const listed = await json(`${BASE}/dev/api/service-providers`);
      assert(listed.some((s) => s.entity_id === sp.entityId), 'not listed after registering');
      const r = await json(`${BASE}/dev/api/response?sp=${encodeURIComponent(sp.entityId)}`);
      assert(r.acs_url === sp.acs && r.encrypted, `minted for ${r.acs_url}, encrypted=${r.encrypted}`);
      return 'listed, used for minting';
    });

    for (const issuer of issuers) {
      process.stderr.write(`${issuer.id}… `);
      await runIssuer(issuer, keys);
    }
    process.stderr.write('rotation…\n');
    await rotation(issuers, keys);
  } finally {
    server.child.kill();
    if (VERBOSE) console.error(server.log());
  }

  // Report.
  const width = Math.max(...results.map((r) => r.name.length));
  let currentIssuer;
  for (const r of results) {
    if (r.issuer !== currentIssuer) {
      currentIssuer = r.issuer;
      console.log(`\n${r.issuer}`);
    }
    console.log(`  ${r.ok ? 'ok  ' : 'FAIL'} ${r.lib.padEnd(9)} ${r.name.padEnd(width)}  ${r.detail.replace(/\s+/g, ' ').slice(0, 140)}`);
  }
  const failures = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failures.length}/${results.length} passed`);
  failed = failures.length > 0;
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
