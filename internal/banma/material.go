package banma

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
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
			fingerprints := []string{}
			for _, match := range csrfValue.FindAllStringSubmatch(string(body), -1) {
				h := sha256.Sum256([]byte(strings.TrimPrefix(match[0], match[1])))
				fingerprints = append(fingerprints, hex.EncodeToString(h[:]))
			}
			v["response_csrf_fingerprints"] = fingerprints
			text := csrfValue.ReplaceAllString(string(body), "${1}[REDACTED]")
			if password != "" {
				text = strings.ReplaceAll(text, `value="`+password+`"`, `value="[REDACTED]"`)
				text = strings.ReplaceAll(text, `value='`+password+`'`, `value='[REDACTED]'`)
			}
			v["body_text"] = text
		}
		// Retain submitted non-secret payloads. Dropping the whole request body
		// made CSRF controls and injection variants impossible to judge.
		if body, err := base64.StdEncoding.DecodeString(toString(v["request_body_base64"])); err == nil && len(body) > 0 {
			if form, err := url.ParseQuery(string(body)); err == nil && strings.Contains(string(body), "=") {
				v["request_form"], v["request_csrf_fingerprints"] = safeRequestForm(form)
			} else {
				var object interface{}
				if json.Unmarshal(body, &object) == nil {
					v["request_json"] = maskRequestJSON(object)
				}
			}
		}
		for _, urlKey := range []string{"url", "input_url", "wire_request_target"} {
			if u, err := url.Parse(toString(v[urlKey])); err == nil && u.RawQuery != "" {
				form, fingerprints := safeRequestForm(u.Query())
				v["request_query"] = form
				v["query_csrf_fingerprints"] = fingerprints
				q := url.Values{}
				for key, values := range form {
					for _, value := range values {
						q.Add(key, value)
					}
				}
				u.RawQuery = q.Encode()
				v[urlKey] = u.String()
			}
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
						if n == "set-cookie" || secretRequestField(n) {
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

func secretRequestField(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "password") || strings.Contains(key, "passwd") || strings.Contains(key, "token") || key == "authorization" || key == "cookie" || strings.Contains(key, "secret") || strings.Contains(key, "api-key") || key == "otp"
}
func safeRequestForm(form url.Values) (map[string][]string, map[string][]string) {
	safe := map[string][]string{}
	fingerprints := map[string][]string{}
	for key, values := range form {
		safe[key] = append([]string{}, values...)
		if !secretRequestField(key) {
			continue
		}
		for i, value := range values {
			h := sha256.Sum256([]byte(value))
			fingerprints[key] = append(fingerprints[key], hex.EncodeToString(h[:]))
			safe[key][i] = "[REDACTED]"
		}
	}
	return safe, fingerprints
}
func maskRequestJSON(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, item := range v {
			if secretRequestField(key) {
				v[key] = "[REDACTED]"
			} else {
				v[key] = maskRequestJSON(item)
			}
		}
	case []interface{}:
		for i, item := range v {
			v[i] = maskRequestJSON(item)
		}
	}
	return value
}
