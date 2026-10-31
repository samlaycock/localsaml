// A crewjam/saml (goxmldsig) service provider for the localsaml interop harness. It reads one JSON
// command per line on stdin and writes one JSON result per line on stdout, so run.mjs can play the
// browser while this process builds requests and validates what localsaml sends back.
package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

type spConfig struct {
	EntityID     string `json:"entity_id"`
	ACS          string `json:"acs"`
	SLO          string `json:"slo"`
	Key          string `json:"key"`
	Cert         string `json:"cert"`
	NameIDFormat string `json:"name_id_format"`
}

type command struct {
	Op           string   `json:"op"`
	IDPMetadata  string   `json:"idp_metadata"`
	SP           spConfig `json:"sp"`
	Binding      string   `json:"binding"`
	Sign         bool     `json:"sign"`
	RelayState   string   `json:"relay_state"`
	SAMLResponse string   `json:"saml_response"`
	RequestIDs   []string `json:"request_ids"`
	NameID       string   `json:"name_id"`
	SessionIndex string   `json:"session_index"`
	SAMLRequest  string   `json:"saml_request"`
	Query        string   `json:"query"`
}

type result map[string]any

func newSP(c command) (*saml.ServiceProvider, error) {
	idp, err := samlsp.ParseMetadata([]byte(c.IDPMetadata))
	if err != nil {
		return nil, fmt.Errorf("idp metadata: %w", err)
	}
	pair, err := tls.X509KeyPair([]byte(c.SP.Cert), []byte(c.SP.Key))
	if err != nil {
		return nil, fmt.Errorf("sp key pair: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	acs, _ := url.Parse(c.SP.ACS)
	slo, _ := url.Parse(c.SP.SLO)
	entity, _ := url.Parse(c.SP.EntityID)
	sp := &saml.ServiceProvider{
		EntityID:          c.SP.EntityID,
		Key:               pair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       cert,
		MetadataURL:       *entity,
		AcsURL:            *acs,
		SloURL:            *slo,
		IDPMetadata:       idp,
		AllowIDPInitiated: true,
		LogoutBindings:    []string{saml.HTTPPostBinding},
	}
	if c.SP.NameIDFormat != "" {
		sp.AuthnNameIDFormat = saml.NameIDFormat(c.SP.NameIDFormat)
	}
	if c.Sign {
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	}
	return sp, nil
}

var formField = regexp.MustCompile(`name="(SAMLRequest|SAMLResponse|RelayState)" value="([^"]*)"`)
var formAction = regexp.MustCompile(`action="([^"]*)"`)

// postForm turns crewjam's auto-submitting HTML into {action, form}.
func postForm(page []byte) result {
	form := map[string]string{}
	for _, m := range formField.FindAllStringSubmatch(string(page), -1) {
		form[m[1]] = unescape(m[2])
	}
	action := ""
	if m := formAction.FindStringSubmatch(string(page)); m != nil {
		action = unescape(m[1])
	}
	return result{"action": action, "form": form}
}

func unescape(s string) string {
	return html.UnescapeString(s)
}

func run(c command) (result, error) {
	sp, err := newSP(c)
	if err != nil {
		return nil, err
	}
	switch c.Op {
	case "login":
		binding := saml.HTTPRedirectBinding
		if c.Binding == "post" {
			binding = saml.HTTPPostBinding
		}
		req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(binding), binding, saml.HTTPPostBinding)
		if err != nil {
			return nil, err
		}
		if binding == saml.HTTPPostBinding {
			r := postForm(req.Post(c.RelayState))
			r["id"] = req.ID
			return r, nil
		}
		u, err := req.Redirect(url.QueryEscape(c.RelayState), sp)
		if err != nil {
			return nil, err
		}
		return result{"id": req.ID, "url": u.String()}, nil

	case "parse_response":
		form := url.Values{"SAMLResponse": {c.SAMLResponse}}
		httpReq, _ := http.NewRequest(http.MethodPost, sp.AcsURL.String(), strings.NewReader(form.Encode()))
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// samlsp's middleware parses the form before ParseResponse reads it.
		if err := httpReq.ParseForm(); err != nil {
			return nil, err
		}
		assertion, err := sp.ParseResponse(httpReq, c.RequestIDs)
		if err != nil {
			var ire *saml.InvalidResponseError
			if errors.As(err, &ire) && ire.PrivateErr != nil {
				return nil, fmt.Errorf("%v", ire.PrivateErr)
			}
			return nil, err
		}
		attrs := map[string][]string{}
		for _, st := range assertion.AttributeStatements {
			for _, a := range st.Attributes {
				for _, v := range a.Values {
					attrs[a.Name] = append(attrs[a.Name], v.Value)
				}
			}
		}
		out := result{"attributes": attrs}
		if assertion.Subject != nil && assertion.Subject.NameID != nil {
			out["name_id"] = assertion.Subject.NameID.Value
			out["name_id_format"] = assertion.Subject.NameID.Format
		}
		for _, st := range assertion.AuthnStatements {
			out["session_index"] = st.SessionIndex
		}
		return out, nil

	case "logout":
		req, err := sp.MakeLogoutRequest(sp.GetSLOBindingLocation(saml.HTTPPostBinding), c.NameID)
		if err != nil {
			return nil, err
		}
		r := postForm(req.Post(c.RelayState))
		r["id"] = req.ID
		return r, nil

	case "handle_logout_request":
		return handleLogoutRequest(sp, c)

	case "parse_logout_response":
		if c.Binding == "redirect" {
			return result{}, sp.ValidateLogoutResponseRedirect(c.SAMLResponse)
		}
		return result{}, sp.ValidateLogoutResponseForm(c.SAMLResponse)
	}
	return nil, fmt.Errorf("unknown op %q", c.Op)
}

// handleLogoutRequest validates a LogoutRequest localsaml posted (propagating another SP's logout)
// and answers it with a signed LogoutResponse over the POST binding. crewjam/saml has no API to
// validate a LogoutRequest as a service provider (only LogoutResponses), so this checks it the way
// crewjam checks those: an enveloped signature by a signing certificate in the IdP's metadata.
func handleLogoutRequest(sp *saml.ServiceProvider, c command) (result, error) {
	raw, err := base64.StdEncoding.DecodeString(c.SAMLRequest)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	if err := verifyIDPSignature(sp, doc.Root()); err != nil {
		return nil, err
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	switch {
	case req.Issuer == nil || req.Issuer.Value != sp.IDPMetadata.EntityID:
		return nil, fmt.Errorf("Issuer %+v, expected %s", req.Issuer, sp.IDPMetadata.EntityID)
	case req.Destination != sp.SloURL.String():
		return nil, fmt.Errorf("Destination %s", req.Destination)
	case req.NotOnOrAfter != nil && !saml.TimeNow().Before(*req.NotOnOrAfter):
		return nil, fmt.Errorf("expired at %s", req.NotOnOrAfter)
	case req.NameID == nil || req.NameID.Value != c.NameID:
		return nil, fmt.Errorf("NameID %+v, expected %s", req.NameID, c.NameID)
	case c.SessionIndex != "" && (req.SessionIndex == nil || req.SessionIndex.Value != c.SessionIndex):
		return nil, fmt.Errorf("SessionIndex %+v, expected %s", req.SessionIndex, c.SessionIndex)
	}
	// crewjam only signs when SignatureMethod is set; the SAML profiles want the answer signed.
	sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	page, err := sp.MakePostLogoutResponse(req.ID, c.RelayState)
	if err != nil {
		return nil, err
	}
	r := postForm(page)
	r["id"] = req.ID
	r["name_id"] = req.NameID.Value
	if req.SessionIndex != nil {
		r["session_index"] = req.SessionIndex.Value
	}
	return r, nil
}

// verifyIDPSignature checks el's enveloped signature against the IdP metadata's signing
// certificates, like crewjam's (unexported) ServiceProvider.validateSignature.
func verifyIDPSignature(sp *saml.ServiceProvider, el *etree.Element) error {
	var certs []*x509.Certificate
	for _, d := range sp.IDPMetadata.IDPSSODescriptors {
		for _, k := range d.KeyDescriptors {
			if k.Use != "" && k.Use != "signing" {
				continue
			}
			for _, x := range k.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(x.Data), ""))
				if err != nil {
					return err
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) == 0 {
		return errors.New("no signing certificate in the IdP metadata")
	}
	if el.FindElement("./Signature") == nil {
		return errors.New("the LogoutRequest is not signed")
	}
	v := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	v.IdAttribute = "ID"
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err == nil {
		ctx, err = ctx.SubContext(el)
	}
	if err == nil {
		el, err = etreeutils.NSDetatch(ctx, el)
	}
	if err == nil {
		_, err = v.Validate(el)
	}
	if err != nil {
		return fmt.Errorf("cannot validate signature on %s: %w", el.Tag, err)
	}
	return nil
}

func main() {
	// localsaml's assertions are checked against real time, like any app.
	saml.TimeNow = func() time.Time { return time.Now().UTC() }
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 16<<20), 16<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var c command
		if err := json.Unmarshal(in.Bytes(), &c); err != nil {
			_ = out.Encode(result{"ok": false, "error": "bad command: " + err.Error()})
			continue
		}
		r, err := run(c)
		if err != nil {
			_ = out.Encode(result{"ok": false, "error": err.Error()})
			continue
		}
		r["ok"] = true
		_ = out.Encode(r)
	}
}
