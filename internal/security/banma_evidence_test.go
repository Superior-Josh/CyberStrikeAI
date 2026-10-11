package security

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

func TestBanmaSaveRejectsInventedSourcesAndBindsNativeEvidence(t *testing.T) {
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("CYBERSTRIKE_ROOT", root)
	python := filepath.Join(project, "venv/bin/python")
	script := `import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1]+"/tools/scripts")
import banma_pentest_run_cases as h
h.ROOT=Path(sys.argv[2]);c,cases=h.catalog(Path(sys.argv[1])/"cases")
r=h.init_run(cases,c,{"test_name":"fixture","test_info":{"targets":["http://127.0.0.1:4280"],"write_authorized":False}})
print(json.dumps(r))`
	output, err := exec.Command(python, "-c", script, project, root).Output()
	if err != nil {
		t.Fatal(err)
	}
	var initialized map[string]interface{}
	if json.Unmarshal(output, &initialized) != nil {
		t.Fatal("fixture init")
	}
	run := initialized["run_dir"].(string)
	source := filepath.Join(run, "evidence/raw/response.json")
	content := []byte(`{"source":"http-framework-test native response capture","status_code":200,"request_headers":[],"headers":[],"body_base64":"T0ZGTElORSBGSVhUVVJF"}`)
	if err = os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := database.NewDB(filepath.Join(root, "test.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := mcp.NewServerWithStorage(zap.NewNop(), db)
	initBody, _ := json.Marshal(map[string]interface{}{"ok": true, "run_dir": run})
	if err = db.SaveToolExecution(&mcp.ToolExecution{ID: "fixture-init", ToolName: "banma_pentest_run_cases", ConversationID: "fixture", Status: "completed", StartTime: time.Now().Add(-time.Second), Arguments: map[string]interface{}{"mode": "init", "payload": map[string]interface{}{"test_info": map[string]interface{}{"targets": []string{"http://127.0.0.1:4280"}, "write_authorized": false}}}, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(initBody)}}}}); err != nil {
		t.Fatal(err)
	}

	id := "00000000-0000-4000-8000-000000000001"
	result := &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "OFFLINE FIXTURE"}}, NativeFiles: []mcp.NativeFileRef{{Path: source, SHA256: nativeHash(content)}}}
	if err = db.SaveToolExecution(&mcp.ToolExecution{ID: id, ToolName: "http-framework-test", ConversationID: "fixture", Status: "completed", StartTime: time.Now(), Result: result}); err != nil {
		t.Fatal(err)
	}
	reviewScript := `import sys
from pathlib import Path
project=sys.argv[1];scratch=sys.argv[2]
sys.path.insert(0,project+"/tools/scripts")
import banma_pentest_run_cases as h
h.ROOT=Path(scratch);sys.argv=["checker",*sys.argv[3:],"--cases-dir",project+"/cases"]
raise SystemExit(h.main())`
	tool := config.ToolConfig{Name: "banma_pentest_run_cases", Command: python, Args: []string{"-c", reviewScript, project, root}, Enabled: true}
	executor := NewExecutor(&config.SecurityConfig{Tools: []config.ToolConfig{tool}}, server, zap.NewNop())
	reviews := 0
	executor.SetBanmaReviewer(func(context.Context, string) (string, error) { reviews++; return `{"approved":true,"issues":[]}`, nil })
	payload := map[string]interface{}{"actual_steps": []interface{}{map[string]interface{}{"execution_id": id, "tool_name": "http-framework-test", "tool_status": "completed"}}, "evidence": []interface{}{map[string]interface{}{"evidence_id": "E1", "source_type": "原始文件", "source_ref": id, "source_path": source}}}
	args := map[string]interface{}{"run_dir": run, "case_id": "PT_WEB_03", "payload": payload}
	ctx := mcp.WithMCPConversationID(context.Background(), "fixture")
	prepared, failure := executor.prepareBanmaSave(ctx, args)
	if failure != nil {
		t.Fatalf("valid native evidence rejected: %s", mcp.ToolResultPlainText(failure))
	}
	bound := prepared["payload"].(map[string]interface{})["evidence"].([]interface{})[0].(map[string]interface{})
	if bound["provenance"] == nil || prepared["payload"].(map[string]interface{})["judgment_review"] == nil || reviews != 1 {
		t.Fatal("runtime provenance/review not bound")
	}
	exported := bound["source_path"].(string)
	stat, err := os.Stat(exported)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("export permissions")
	}
	operation := payload["actual_steps"].([]interface{})[0].(map[string]interface{})
	operation["tool_name"] = "execute-python-script"
	if _, bad := executor.prepareBanmaSave(ctx, args); bad == nil {
		t.Fatal("invented tool accepted")
	}
	operation["tool_name"] = "http-framework-test"
	if err = os.WriteFile(source, []byte("MODEL SUMMARY"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, bad := executor.prepareBanmaSave(ctx, args); bad == nil {
		t.Fatal("rewritten native source accepted")
	}
	if reviews != 1 {
		t.Fatal("untrusted evidence reached semantic reviewer")
	}
	if err = os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	executor.SetBanmaReviewer(func(context.Context, string) (string, error) {
		return `{"approved":false,"issues":["invalid CSRF normal control"]}`, nil
	})
	if _, bad := executor.prepareBanmaSave(ctx, args); bad == nil || !strings.Contains(mcp.ToolResultPlainText(bad), "JUDGMENT_REJECTED") {
		t.Fatal("rejected judgment allowed")
	}
	if _, bad := executor.prepareBanmaSave(mcp.WithMCPConversationID(context.Background(), "another"), args); bad == nil {
		t.Fatal("cross-conversation evidence accepted")
	}
}

func TestBanmaBoundaryChecksConcreteCallsBeforeExecution(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "guard.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := mcp.NewServerWithStorage(zap.NewNop(), db)
	native := &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: `{"ok":true,"run_dir":"/fixture"}`}}}
	init := &mcp.ToolExecution{ID: "init", ToolName: "banma_pentest_run_cases", ConversationID: "fixture", Status: "completed", StartTime: time.Now(), Arguments: map[string]interface{}{"mode": "init", "payload": map[string]interface{}{"test_info": map[string]interface{}{"targets": []string{"http://127.0.0.1:4280"}, "write_authorized": false}}}, Result: native}
	if err = db.SaveToolExecution(init); err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(&config.SecurityConfig{}, server, zap.NewNop())
	ctx := mcp.WithMCPConversationID(context.Background(), "fixture")
	for _, url := range []string{"http://127.0.0.1:4280/.env", "http://127.0.0.1:4280/%252egit/config", "http://127.0.0.1:4040/", "http://example.com:4280/"} {
		if executor.checkBanmaCall(ctx, "http-framework-test", map[string]interface{}{"url": url}) == nil {
			t.Fatalf("forbidden URL accepted: %s", url)
		}
	}
	if executor.checkBanmaCall(ctx, "http-framework-test", map[string]interface{}{"url": "http://localhost:4280/login.php", "capture_file": "/fixture/evidence/raw/normal.json"}) != nil {
		t.Fatal("same authorized loopback endpoint denied")
	}
	if executor.checkBanmaCall(ctx, "http-framework-test", map[string]interface{}{"url": "http://127.0.0.1:4280/.env", "method": "HEAD", "capture_file": "/fixture/evidence/raw/head.json"}) != nil {
		t.Fatal("non-content HEAD probe denied")
	}
	if executor.checkBanmaCall(ctx, "exec", map[string]interface{}{"command": "find /Users/banma-josh/project/CyberStrikeAI/reports/fixture/evidence/raw -type f"}) != nil {
		t.Fatal("own evidence search incorrectly denied")
	}
	if executor.checkBanmaCall(ctx, "exec", map[string]interface{}{"command": "find / -name config.inc.php"}) == nil {
		t.Fatal("white-box search allowed")
	}
	if executor.checkBanmaCall(ctx, "http-framework-test", map[string]interface{}{"url": "http://127.0.0.1:4280/profile", "method": "POST"}) == nil {
		t.Fatal("read-only business write allowed")
	}
	if executor.checkBanmaCall(context.Background(), "http-framework-test", map[string]interface{}{"url": "http://example.com/"}) != nil {
		t.Fatal("other roles changed")
	}
}
