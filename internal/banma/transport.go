package banma

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/mcp"
)

// Native plaintext submission of the supplied credential is a computable
// failure. Remaining TLS/Cookie/recovery checks retain their own coverage gaps.
func PlaintextCredentialDecision(guide map[string]interface{}, records []*mcp.ToolExecution, username, password string) (Decision, bool, error) {
	c, _ := guide["case"].(map[string]interface{})
	if c["id"] != "PT_WEB_AUTH_21" || username == "" || password == "" {
		return Decision{}, false, nil
	}
	type frame struct {
		capture Capture
		index   int
	}
	frames := []frame{}
	for index, record := range records {
		if record == nil || record.ToolName != "http-framework-test" || record.Status != "completed" || record.Result == nil || record.Result.IsError {
			continue
		}
		for _, ref := range record.Result.NativeFiles {
			single := *record
			result := *record.Result
			result.NativeFiles = []mcp.NativeFileRef{ref}
			single.Result = &result
			capture, err := ReadCapture(&single)
			if err != nil {
				return Decision{}, true, err
			}
			frames = append(frames, frame{capture, index})
		}
	}
	for _, current := range frames {
		capture, index := current.capture, current.index
		target, err := url.Parse(capture.URL)
		if err != nil || target.Scheme != "http" {
			continue
		}
		body, err := base64.StdEncoding.DecodeString(capture.RequestBody)
		if err != nil {
			return Decision{}, true, err
		}
		form, _ := url.ParseQuery(string(body))
		if !form.Has("password") {
			var object map[string]interface{}
			if json.Unmarshal(body, &object) == nil {
				for _, key := range []string{"username", "password"} {
					if value, ok := object[key].(string); ok {
						form.Set(key, value)
					}
				}
			}
		}
		if !form.Has("password") {
			form = target.Query()
		}
		if form.Get("username") == username && form.Get("password") == password {
			old := sessionCookies(capture.RequestHeaders, false)
			issued := sessionCookies(capture.Headers, true)
			if len(issued) == 0 {
				issued = old
			}
			preIndex, postIndex := -1, -1
			for _, other := range frames {
				u, _ := url.Parse(other.capture.URL)
				if u == nil || u.Host != target.Host {
					continue
				}
				body, _ := base64.StdEncoding.DecodeString(other.capture.Body)
				if other.capture.Time < capture.Time && len(sessionCookies(other.capture.RequestHeaders, false)) == 0 && matchingSession(sessionCookies(other.capture.Headers, true), old) && loginFormWithoutIdentity(other.capture.Body, username) {
					preIndex = other.index
				}
				if other.capture.Time > capture.Time && other.capture.Status == 200 && matchingSession(sessionCookies(other.capture.RequestHeaders, false), issued) && observedIdentity(string(body), username) && strings.Contains(string(body), "logout.php") {
					postIndex = other.index
				}
			}
			if preIndex < 0 || postIndex < 0 {
				continue
			}
			return Decision{Method: "code", Checks: []Check{{Ref: "steps[0]", Result: "失败", Reason: "同轮真实原生请求使用HTTP并提交用户提供的口令，不满足本项敏感请求HTTPS基线；秘密值不展示", Evidence: []int{preIndex, index, postIndex}}}, Gaps: []string{"其余传输/TLS/Cookie条款及原会话清理尚待核验"}, Recovery: "待确认"}, true, nil
		}
	}
	return Decision{}, false, nil
}

func sessionCookies(headers [][]string, response bool) map[string]string {
	found := map[string]string{}
	for _, pair := range headers {
		if len(pair) != 2 {
			continue
		}
		h := http.Header{}
		if response && strings.EqualFold(pair[0], "set-cookie") {
			h.Add("Set-Cookie", pair[1])
			for _, c := range (&http.Response{Header: h}).Cookies() {
				if strings.Contains(strings.ToLower(c.Name), "sess") && c.Value != "" {
					found[c.Name] = c.Value
				}
			}
		}
		if !response && strings.EqualFold(pair[0], "cookie") {
			h.Add("Cookie", pair[1])
			for _, c := range (&http.Request{Header: h}).Cookies() {
				if strings.Contains(strings.ToLower(c.Name), "sess") && c.Value != "" {
					found[c.Name] = c.Value
				}
			}
		}
	}
	return found
}
func matchingSession(a, b map[string]string) bool {
	for key, value := range a {
		if value != "" && b[key] == value {
			return true
		}
	}
	return false
}

var identityTags = regexp.MustCompile(`<[^>]*>`)

func observedIdentity(body, username string) bool {
	text := " " + strings.Join(strings.Fields(html.UnescapeString(identityTags.ReplaceAllString(body, " "))), " ") + " "
	return strings.Contains(text, " Username: "+username+" ") || strings.Contains(text, " You have logged in as "+username+" ")
}
func loginFormWithoutIdentity(encoded, username string) bool {
	_, _, err := formFields(encoded)
	body, _ := base64.StdEncoding.DecodeString(encoded)
	return err == nil && !observedIdentity(string(body), username)
}
