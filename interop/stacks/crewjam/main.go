// A crewjam/saml (goxmldsig) service provider for the localsaml interop harness. It reads one JSON
// command per line on stdin and writes one JSON result per line on stdout, so run.mjs can play the
// browser while this process builds requests and validates what localsaml sends back.
package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
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

	case "parse_logout_response":
		if c.Binding == "redirect" {
			return result{}, sp.ValidateLogoutResponseRedirect(c.SAMLResponse)
		}
		return result{}, sp.ValidateLogoutResponseForm(c.SAMLResponse)
	}
	return nil, fmt.Errorf("unknown op %q", c.Op)
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
