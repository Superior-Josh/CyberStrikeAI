package handler

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

func TestBanmaCompletionBoundToExecutionsAndUsesRealChecker(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(root, "venv/bin/python")
	scratch := t.TempDir()
	fixture := `import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1]+"/tools/scripts")
import banma_pentest_run_cases as h
h.ROOT=Path(sys.argv[2])
context,cases=h.catalog(Path(sys.argv[1])/"cases")
print(json.dumps(h.init_run(cases,context,{"test_name":"fixture","test_info":{"targets":["OFFLINE-NO-TARGET"]}})))`
	output, err := exec.Command(python, "-c", fixture, root, scratch).Output()
	if err != nil {
		t.Fatal(err)
	}
	var initialized map[string]interface{}
	if err = json.Unmarshal(output, &initialized); err != nil {
		t.Fatal(err)
	}
	initialized["ok"] = true
	result, _ := json.Marshal(initialized)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "completion.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	checker := `import sys
from pathlib import Path
root=sys.argv[1];scratch=sys.argv[2]
sys.path.insert(0,root+"/tools/scripts")
import banma_pentest_run_cases as h
h.ROOT=Path(scratch)
sys.argv=["checker",*sys.argv[3:],"--cases-dir",root+"/cases"]
raise SystemExit(h.main())`
	h := &AgentHandler{db: db, config: &config.Config{Security: config.SecurityConfig{Tools: []config.ToolConfig{{Name: "banma_pentest_run_cases", Enabled: true, Command: python, Args: []string{"-c", checker, root, scratch}}}}}}
	execution := &mcp.ToolExecution{ID: "fixture-init", ConversationID: "fixture-conversation", ToolName: "banma_pentest_run_cases", Arguments: map[string]interface{}{"mode": "init", "payload": map[string]interface{}{"test_info": map[string]interface{}{"targets": []string{"OFFLINE-NO-TARGET"}}}}, Status: "completed", StartTime: time.Now(), Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(result)}}}}
	if err = db.SaveToolExecution(execution); err != nil {
		t.Fatal(err)
	}
	d := h.decideAgentRunForDelivery("fixture-conversation", "", "eino_single", nil, []string{execution.ID})
	// No candidate text is normally blocked before calling the checker; supply one through the policy wrapper.
	runs, err := h.fixedCaseCheckFor("fixture-conversation")([]string{execution.ID})
	if err != nil || len(runs) != 1 || len(runs[0].PendingCaseIDs) != 44 {
		t.Fatalf("real checker: %+v %v", runs, err)
	}
	d = agentfinalizer.Decide(db, agentfinalizer.Input{Response: "finished", MCPExecutionIDs: []string{execution.ID}, FixedCaseCheck: h.fixedCaseCheckFor("fixture-conversation")})
	if d.Finalized || d.CompletionReason != agentfinalizer.ReasonPendingCases {
		t.Fatalf("empty checklist finalized: %+v", d)
	}
	metaPath := filepath.Join(initialized["run_dir"].(string), "evidence/test_info.json")
	original, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]interface{}
	if json.Unmarshal(original, &meta) != nil {
		t.Fatal("invalid fixture metadata")
	}
	meta["test_info"].(map[string]interface{})["case_ids"] = []string{"PT_WEB_01"}
	reduced, _ := json.Marshal(meta)
	if os.WriteFile(metaPath, reduced, 0600) != nil {
		t.Fatal("cannot edit fixture")
	}
	if _, err = h.fixedCaseCheckFor("fixture-conversation")([]string{execution.ID}); err == nil {
		t.Fatal("edited metadata silently narrowed original full scope")
	}
	if err = os.WriteFile(metaPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	// A later explanation with no tool executions must not restart this old task.
	runs, err = h.fixedCaseCheckFor("fixture-conversation")(nil)
	if err != nil || len(runs) != 0 {
		t.Fatalf("unrelated turn bound to old report: %+v %v", runs, err)
	}
	_, err = h.fixedCaseCheckFor("other-conversation")([]string{execution.ID})
	if err == nil {
		t.Fatal("cross-conversation execution accepted")
	}
	execution.Arguments = map[string]interface{}{"mode": "list", "run_dir": initialized["run_dir"]}
	if err = db.SaveToolExecution(execution); err != nil {
		t.Fatal(err)
	}
	runs, err = h.fixedCaseCheckFor("fixture-conversation")([]string{execution.ID})
	if err != nil || len(runs) != 0 {
		t.Fatal("read-only list follow-up must not trigger tests")
	}
}
