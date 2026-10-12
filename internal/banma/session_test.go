package banma

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func TestAuthenticationPreparationBindsFreshCSRFAndRotatedSession(t *testing.T) {
	r := &Runner{RunDir: t.TempDir()}
	count := 0
	r.Call = func(_ context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
		count++
		capture := Capture{URL: args["url"].(string), Time: float64(count), Method: args["method"].(string)}
		headers, _ := args["headers"].(map[string]string)
		switch count {
		case 1:
			capture.Status = 302
			capture.Headers = [][]string{{"Location", "/login.php"}, {"Set-Cookie", "PHPSESSID=anonymous; HttpOnly"}}
		case 2:
			if headers["Cookie"] != "PHPSESSID=anonymous" {
				t.Fatal("discovery cookie lost")
			}
			capture.Status = 200
			capture.Body = base64.StdEncoding.EncodeToString([]byte(`<title>DVWA</title><form action="login.php"><input name="username"><input type="password" name="password"><input type="hidden" name="user_token" value="fresh-token"><input name="Login" value="Login"></form>`))
		case 3:
			fields, _ := url.ParseQuery(args["data"].(string))
			if fields.Get("user_token") != "fresh-token" || fields.Get("username") != "fixture" || fields.Get("password") != "provided" || headers["Cookie"] != "PHPSESSID=anonymous" {
				t.Fatal("credentials/CSRF/session not bound")
			}
			capture.Status = 302
			capture.Headers = [][]string{{"Location", "index.php"}, {"Set-Cookie", "PHPSESSID=authenticated; HttpOnly"}}
		case 4:
			if headers["Cookie"] != "PHPSESSID=authenticated" {
				t.Fatal("rotated cookie lost")
			}
			capture.Status = 200
			capture.Body = base64.StdEncoding.EncodeToString([]byte(`<div>Username: <em>fixture</em></div><a href="logout.php">Logout</a>`))
		default:
			t.Fatal("unexpected authentication retry")
		}
		raw, _ := json.Marshal(capture)
		p := args["capture_file"].(string)
		os.MkdirAll(filepath.Dir(p), 0700)
		os.WriteFile(p, raw, 0600)
		h := sha256.Sum256(raw)
		e := fixtureExecution(name, nil)
		e.Result.NativeFiles = []mcp.NativeFileRef{{Path: p, SHA256: hex.EncodeToString(h[:])}}
		return e, nil
	}
	session, err := r.prepareAuthenticatedSession(context.Background(), "PT_WEB_AUTH_06", Input{Targets: []string{"http://fixture.invalid/"}, Username: "fixture", Password: "provided"})
	if err != nil || session == nil || session["status"] != "identity_verified" || count != 4 || len(r.captures) != 4 {
		t.Fatalf("preparation failed: %+v %v", session, err)
	}
}

func TestMissingCredentialsDoNotTriggerRequests(t *testing.T) {
	r := &Runner{Call: func(context.Context, string, map[string]interface{}) (*mcp.ToolExecution, error) {
		t.Fatal("empty credentials requested target")
		return nil, nil
	}}
	session, err := r.prepareAuthenticatedSession(context.Background(), "PT_WEB_AUTH_06", Input{Targets: []string{"http://fixture.invalid/"}})
	if err != nil || session != nil {
		t.Fatal("missing optional input invented session")
	}
}

func TestStoppedCredentialsAreNotRetriedByNextCaseOrHandoff(t *testing.T) {
	r := &Runner{input: Input{Username: "fixture", Password: "provided"}}
	r.stopNormalCredentials()
	r.Call = func(context.Context, string, map[string]interface{}) (*mcp.ToolExecution, error) {
		t.Fatal("next case retried stopped credentials")
		return nil, nil
	}
	session, err := r.prepareAuthenticatedSession(context.Background(), "PT_WEB_AUTH_07", Input{Targets: []string{"http://fixture.invalid/"}, Username: "fixture", Password: "provided"})
	if err != nil || session["status"] != "unavailable" {
		t.Fatal("credential gap was not preserved")
	}
	if r.checkOperation("http-framework-test", map[string]interface{}{"url": "http://fixture.invalid/login.php", "method": "POST", "data": "username=fixture&password=provided"}) == nil {
		t.Fatal("handoff repeated rejected supplied credential")
	}
}
