package banma

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func TestPlaintextCredentialFailureNeedsRealAuthenticatedControl(t *testing.T) {
	for _, test := range []struct {
		scheme, password                 string
		authenticated, found, redirected bool
	}{{"http", "supplied", true, true, false}, {"https", "supplied", true, false, false}, {"http", "candidate", true, false, false}, {"http", "supplied", false, false, false}, {"http", "supplied", true, true, true}} {
		dir := t.TempDir()
		records := []*mcp.ToolExecution{}
		encode := func(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }
		captures := []Capture{
			{Method: "GET", Status: 200, URL: test.scheme + "://example.invalid/login", Time: 1, Headers: [][]string{{"Set-Cookie", "PHPSESSID=anon; HttpOnly"}}, Body: encode(`<form><input name="username"><input name="password" type="password"></form>`)},
			{Method: "POST", Status: 302, URL: test.scheme + "://example.invalid/login", Time: 2, RequestHeaders: [][]string{{"Cookie", "PHPSESSID=anon"}}, Headers: [][]string{{"Set-Cookie", "PHPSESSID=authenticated; HttpOnly"}}, RequestBody: encode("username=fixture&password=" + test.password)},
		}
		if test.redirected {
			captures[0].Headers = nil
			captures[0].RequestHeaders = [][]string{{"Cookie", "PHPSESSID=anon"}}
			captures = append([]Capture{{Method: "GET", Status: 302, URL: test.scheme + "://example.invalid/", Time: 0.5, Headers: [][]string{{"Set-Cookie", "PHPSESSID=anon; HttpOnly"}, {"Location", "login"}}}}, captures...)
		}
		if test.authenticated {
			captures = append(captures, Capture{Method: "GET", Status: 200, URL: test.scheme + "://example.invalid/index", Time: 3, RequestHeaders: [][]string{{"Cookie", "PHPSESSID=authenticated"}}, Body: encode(`<div>Username: <em>fixture</em></div><a href="logout.php">Logout</a>`)})
		}
		for i, c := range captures {
			p := filepath.Join(dir, fmt.Sprint(i)+".json")
			raw, _ := json.Marshal(c)
			os.WriteFile(p, raw, 0600)
			h := sha256.Sum256(raw)
			e := fixtureExecution("http-framework-test", nil)
			e.Result.NativeFiles = []mcp.NativeFileRef{{Path: p, SHA256: hex.EncodeToString(h[:])}}
			records = append(records, e)
		}
		g := map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_AUTH_21", "steps": []interface{}{"sensitive transport", "TLS", "cookie controls"}}}
		d, found, err := PlaintextCredentialDecision(g, records, "fixture", "supplied")
		if err != nil || found != test.found {
			t.Fatalf("incorrect transport decision: %+v %v", test, err)
		}
		if found {
			r := &Runner{captures: records}
			p, err := r.payload(d, g)
			if err != nil || p["coverage_complete"] != false || p["result"] != "失败" || d.Method != "code" || len(d.Checks[0].Evidence) != map[bool]int{false: 3, true: 4}[test.redirected] {
				t.Fatalf("failure lost or falsely complete: %+v %v", p, err)
			}
		}
	}
}
