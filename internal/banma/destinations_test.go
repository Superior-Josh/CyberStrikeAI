package banma

import (
	"crypto/sha256"
	"cyberstrike-ai/internal/mcp"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPPayloadCannotTriggerUnapprovedDestinations(t *testing.T) {
	r := &Runner{input: Input{Targets: []string{"http://127.0.0.1:4280"}}}
	for _, target := range []string{"http://127.0.0.1:4280/?page=http%3A%2F%2Fexample.com", "http://127.0.0.1:4280/?page=http%3A%2F%2F127.0.0.1%3A4280%2Fredir%3Fnext%3Dhttp%3A%2F%2Fexample.com", "http://127.0.0.1:4280/?page=file%3A%2F%2F%2Fetc%2Fpasswd", "http://127.0.0.1:4280/?page=php%3A%2F%2Ffilter%2Fresource%3Dindex.php", "http://127.0.0.1:4280/?url=http%3A%2F%2F127.0.0.1%3A9999"} {
		if r.checkOperation("http-framework-test", map[string]interface{}{"url": target, "method": "GET"}) == nil {
			t.Fatal("unapproved payload accepted")
		}
	}
	if r.checkOperation("http-framework-test", map[string]interface{}{"url": "http://127.0.0.1:4280/", "method": "POST", "data": `{"url":"https:\/\/example.com/"}`}) == nil {
		t.Fatal("JSON destination bypass")
	}
	if r.checkOperation("http-framework-test", map[string]interface{}{"url": "http://127.0.0.1:4280/?redirect=http%3A%2F%2F127.0.0.1%3A4280%2Fsafe", "method": "GET", "headers": map[string]string{"Origin": "https://example.com"}}) != nil {
		t.Fatal("authorized control denied")
	}
}

func TestBareHostPayloadDoesNotInheritHTTPPortAuthorization(t *testing.T) {
	r := &Runner{input: Input{Targets: []string{"http://127.0.0.1:4280"}}}
	for _, data := range []string{"ip=8.8.8.8", "ip=127.0.0.1", "ip=127.0.0.1%3Becho+marker", `{"host":"::1"}`} {
		if r.checkOperation("http-framework-test", map[string]interface{}{"url": "http://127.0.0.1:4280/vulnerabilities/exec/", "method": "POST", "data": data}) == nil {
			t.Fatal("bare network target accepted", data)
		}
	}
}

func TestRelativeExternalURLAndInternalFileProbesAreRejected(t *testing.T) {
	r := &Runner{input: Input{Targets: []string{"http://127.0.0.1:4280"}}}
	for _, data := range []string{"redirect=%2F%2Fevil.example", "page=..%2F..%2Fetc%2Fpasswd", "page=..%2F..%2Fvar%2Fwww%2Fhtml%2Fconfig.php"} {
		if r.checkOperation("http-framework-test", map[string]interface{}{"url": "http://127.0.0.1:4280/", "method": "POST", "data": data}) == nil {
			t.Fatal("out-of-scope probe accepted", data)
		}
	}
}

func TestHistoricalForbiddenPayloadCannotValidateOldPass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.json")
	raw, _ := json.Marshal(Capture{URL: "http://127.0.0.1:4280/?page=file%3A%2F%2F%2Fetc%2Fpasswd", Status: 200})
	os.WriteFile(path, raw, 0600)
	hash := sha256.Sum256(raw)
	e := fixtureExecution("http-framework-test", nil)
	e.Result.NativeFiles = []mcp.NativeFileRef{{Path: path, SHA256: hex.EncodeToString(hash[:])}}
	normal, _ := json.Marshal(Capture{URL: "http://127.0.0.1:4280/", Status: 200})
	normalPath := filepath.Join(dir, "normal.json")
	os.WriteFile(normalPath, normal, 0600)
	normalHash := sha256.Sum256(normal)
	e.Result.NativeFiles = append([]mcp.NativeFileRef{{Path: normalPath, SHA256: hex.EncodeToString(normalHash[:])}}, e.Result.NativeFiles...)
	r := &Runner{captures: []*mcp.ToolExecution{e}}
	guide := map[string]interface{}{"execution_scope": map[string]interface{}{"targets": []string{"http://127.0.0.1:4280"}}}
	if err := r.reviewScope(guide); err == nil || !strings.Contains(err.Error(), "违反冻结授权") {
		t.Fatal("historically unauthorized evidence accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("historical original changed")
	}
}
