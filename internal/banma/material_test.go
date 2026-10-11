package banma

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func TestEvidenceViewRetainsRealPayloadAndMasksSubmittedSecrets(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{"source": "http-framework-test", "url": "http://example.invalid/?id=1%27+OR+1%3D1&user_token=csrf-secret", "input_url": "http://example.invalid/?user_token=csrf-secret", "wire_request_target": "/?user_token=csrf-secret", "wire_request_target_base64": base64.StdEncoding.EncodeToString([]byte("/?user_token=csrf-secret")), "request_headers": [][]string{{"X-CSRF-Token", "csrf-secret"}}, "request_body_base64": base64.StdEncoding.EncodeToString([]byte("id=1%27+OR+1%3D1&password=credential&user_token=csrf-secret")), "body_base64": base64.StdEncoding.EncodeToString([]byte("CONTROL RESPONSE"))})
	p := filepath.Join(t.TempDir(), "native.json")
	os.WriteFile(p, raw, 0600)
	hash := sha256.Sum256(raw)
	record := fixtureExecution("http-framework-test", nil)
	record.Result.NativeFiles = []mcp.NativeFileRef{{Path: p, SHA256: hex.EncodeToString(hash[:])}}
	views := EvidenceView(record, "credential")
	if len(views) != 1 {
		t.Fatal("missing native view")
	}
	if _, ok := views[0]["wire_request_target_base64"]; ok {
		t.Fatal("encoded alternate secret copy retained")
	}
	form := views[0]["request_form"].(map[string][]string)
	if form["id"][0] != "1' OR 1=1" {
		t.Fatal("payload lost")
	}
	encoded, _ := json.Marshal(views)
	if strings.Contains(string(encoded), "csrf-secret") || strings.Contains(string(encoded), "credential") {
		t.Fatal("secret leaked")
	}
	if _, ok := views[0]["request_token_fingerprints"].(map[string][]string)["password"]; ok {
		t.Fatal("unnecessary password hash exposed")
	}
	if len(views[0]["request_token_fingerprints"].(map[string][]string)["user_token"]) != 1 {
		t.Fatal("CSRF comparison lost")
	}
	if _, err := ReadCapture(record); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(raw) {
		t.Fatal("native original changed")
	}
	os.WriteFile(p, []byte(`{"status_code":200}`), 0600)
	if _, err := ReadCapture(record); err == nil {
		t.Fatal("mutated native capture used for judgment")
	}
}
