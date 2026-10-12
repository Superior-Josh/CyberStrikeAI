package banma

import (
	"context"
	"crypto/sha256"
	"cyberstrike-ai/internal/mcp"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestQueryPairsRefreshCSRFAndLeaveSemanticJudgmentReadOnly(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{RunDir: dir, session: map[string]interface{}{"headers": map[string]string{"Cookie": "PHPSESSID=fixture"}, "username": "fixture", "authenticated_url": "http://fixture.invalid/index.php"}}
	makeRecord := func(c Capture, p string) *mcp.ToolExecution {
		raw, _ := json.Marshal(c)
		os.MkdirAll(filepath.Dir(p), 0700)
		os.WriteFile(p, raw, 0600)
		h := sha256.Sum256(raw)
		e := fixtureExecution("http-framework-test", nil)
		e.Result.NativeFiles = []mcp.NativeFileRef{{Path: p, SHA256: hex.EncodeToString(h[:])}}
		return e
	}
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	r.captures = []*mcp.ToolExecution{makeRecord(Capture{URL: "http://fixture.invalid/index.php", Body: enc(`<a href="vulnerabilities/sqli/">query</a><a href="vulnerabilities/sqli_blind/">blind</a>`)}, filepath.Join(dir, "menu.json"))}
	n := 0
	token := ""
	submitted := []string{}
	r.Call = func(_ context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
		n++
		u, _ := url.Parse(args["url"].(string))
		c := Capture{URL: u.String(), Method: "GET", Status: 200}
		if u.RawQuery == "" {
			token = fmt.Sprint(n)
			c.Body = enc(`<form method="GET"><input name="id"><input name="Submit" value="Submit"><input type="hidden" name="user_token" value="` + token + `"></form>`)
		} else {
			q := u.Query()
			if q.Get("user_token") != token || q.Get("Submit") != "Submit" {
				t.Fatal("fresh form token or submit value lost")
			}
			submitted = append(submitted, q.Get("id"))
			c.Body = enc(`<p>Username: fixture</p>`)
		}
		return makeRecord(c, args["capture_file"].(string)), nil
	}
	g := map[string]interface{}{"case": map[string]interface{}{"query_budget": map[string]interface{}{"rounds": 2, "max_requests": 30, "timeout_seconds": 5, "normal_value": "1", "true_value": "true-variant", "false_value": "false-variant"}}}
	_, supported, err := r.prepareQueryChecks(context.Background(), g)
	if err != nil || supported || !r.preparedOnly || n != 28 || len(submitted) != 14 {
		t.Fatalf("pairs/readonly handoff mismatch: %d %v", n, err)
	}
	want := []string{"1", "true-variant", "false-variant", "1", "true-variant", "false-variant", "1"}
	for i, v := range submitted {
		if v != want[i%7] {
			t.Fatal("pair ordering changed")
		}
	}
}
func TestUnknownQueryFormDoesNotInventBinding(t *testing.T) {
	for _, body := range []string{`<form><input name="id"></form>`, `<form action="https://elsewhere.invalid/"><input name="id"><input name="user_token" value="token"></form>`} {
		if _, err := observedQueryForm(body, "http://fixture.invalid/query"); err == nil {
			t.Fatal("guessed form accepted")
		}
	}
}

func TestQueryBudgetIsSharedAcrossCodeAndHandoff(t *testing.T) {
	r := &Runner{currentCase: "PT_WEB_AUTH_08", budget: Budget{QueryCase: "PT_WEB_AUTH_08", QueryMax: 2}}
	args := map[string]interface{}{"url": "http://fixture.invalid/query", "method": "GET"}
	if r.checkOperation("http-framework-test", args) != nil {
		t.Fatal("first query blocked")
	}
	r.budget.Handoff = true
	if r.checkOperation("http-framework-test", args) != nil || r.checkOperation("http-framework-test", args) == nil {
		t.Fatal("handoff reset query budget")
	}
}
