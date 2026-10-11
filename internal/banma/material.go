package banma

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/mcp"
)

var csrfValue = regexp.MustCompile(`(?i)(name=["'](?:user_token|csrf_token|xsrf_token)["']\s+value=["'])[^"']+`)

// EvidenceView decodes native HTTP files for the same Eino judgment. It does not
// create evidence or replace the registered original file and acquisition hash.
func EvidenceView(record *mcp.ToolExecution, password string) []map[string]interface{} {
	views := []map[string]interface{}{}
	if record == nil || record.Result == nil {
		return views
	}
	for _, ref := range record.Result.NativeFiles {
		raw, err := os.ReadFile(ref.Path)
		if err != nil {
			continue
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != ref.SHA256 {
			continue
		}
		var v map[string]interface{}
		if json.Unmarshal(raw, &v) != nil {
			continue
		}
		if !strings.HasPrefix(toString(v["source"]), "http-framework-test") {
			continue
		}
		if body, err := base64.StdEncoding.DecodeString(toString(v["body_base64"])); err == nil {
			text := csrfValue.ReplaceAllString(string(body), "${1}[REDACTED]")
			if password != "" {
				text = strings.ReplaceAll(text, `value="`+password+`"`, `value="[REDACTED]"`)
				text = strings.ReplaceAll(text, `value='`+password+`'`, `value='[REDACTED]'`)
			}
			v["body_text"] = text
		}
		delete(v, "request_body_base64")
		delete(v, "body_base64")
		attrs := []map[string]interface{}{}
		if pairs, ok := v["headers"].([]interface{}); ok {
			for _, raw := range pairs {
				if p, ok := raw.([]interface{}); ok && len(p) == 2 && strings.EqualFold(toString(p[0]), "set-cookie") {
					headers := http.Header{}
					headers.Add("Set-Cookie", toString(p[1]))
					for _, cookie := range (&http.Response{Header: headers}).Cookies() {
						hash := sha256.Sum256([]byte(cookie.Value))
						attrs = append(attrs, map[string]interface{}{"name": cookie.Name, "secure": cookie.Secure, "http_only": cookie.HttpOnly, "same_site": int(cookie.SameSite), "path": cookie.Path, "domain": cookie.Domain, "value_fingerprint": hex.EncodeToString(hash[:])})
					}
				}
			}
		}
		v["cookie_attributes"] = attrs
		for _, key := range []string{"headers", "request_headers"} {
			if pairs, ok := v[key].([]interface{}); ok {
				for _, raw := range pairs {
					if p, ok := raw.([]interface{}); ok && len(p) == 2 {
						n := strings.ToLower(toString(p[0]))
						if n == "cookie" || n == "set-cookie" || n == "authorization" {
							p[1] = "[REDACTED]"
						}
					}
				}
			}
		}
		v["source_path"] = ref.Path
		v["native_sha256"] = ref.SHA256
		v["view_kind"] = "decoded view of registered native HTTP file; original retained"
		views = append(views, v)
	}
	return views
}
