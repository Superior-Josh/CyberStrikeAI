package banma

import (
	"context"
	"crypto/sha256"
	"cyberstrike-ai/internal/mcp"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPlaintextFormFailureDoesNotSendSecretsAndStillRequiresGapAnalysis(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		r := &Runner{RunDir: t.TempDir()}
		calls := 0
		r.Call = func(_ context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
			calls++
			if args["method"] != "GET" || toString(args["data"]) != "" {
				t.Fatal("unexpected secret submission")
			}
			c := Capture{URL: args["url"].(string), Status: 200, Body: base64.StdEncoding.EncodeToString([]byte(`<form action="login.php"><input name="username"><input name="password" type="password"></form>`))}
			raw, _ := json.Marshal(c)
			p := args["capture_file"].(string)
			os.MkdirAll(filepath.Dir(p), 0700)
			os.WriteFile(p, raw, 0600)
			hash := sha256.Sum256(raw)
			e := fixtureExecution(name, nil)
			e.Result.NativeFiles = []mcp.NativeFileRef{{Path: p, SHA256: hex.EncodeToString(hash[:])}}
			return e, nil
		}
		_, supported, err := r.observePlaintextLoginForm(context.Background(), Input{Targets: []string{scheme + "://fixture.invalid/"}, Username: "fixture", Password: "secret"})
		if err != nil || supported || calls != 1 || (r.codeDecision != nil) != (scheme == "http") {
			t.Fatal("failure or Eino handoff mismatch")
		}
	}
}
func TestLoginFieldsCannotCrossFormBoundaries(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	raw := `<form action="login.php"><input name="username"><input type="password" name="password"><input name="user_token" value="fresh"></form><form action="reset.php"><input name="user_token" value="unrelated"></form>`
	fields, action, err := formFields(enc(raw))
	if err != nil || action != "login.php" || fields.Get("user_token") != "fresh" {
		t.Fatal("unrelated form contaminated login")
	}
	if _, _, err = formFields(enc(`<form><input name="username"></form><form><input name="password" type="password"></form>`)); err == nil {
		t.Fatal("split form credentials invented")
	}
	if _, _, err = formFields(enc(`<form><input name="username"><input name="password" type="password" disabled></form>`)); err == nil {
		t.Fatal("disabled credential input adopted")
	}
}
