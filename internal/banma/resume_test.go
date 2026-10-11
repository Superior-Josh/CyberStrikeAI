package banma

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func TestResumePreservesChecklistAndNeverReplaysAttemptedCase(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "evidence/raw/PT_WEB_AUTH_17"), 0700)
	os.MkdirAll(filepath.Join(dir, "evidence/raw/PT_WEB_02"), 0700)
	input := Input{ResumeRunDir: dir, Targets: []string{"http://127.0.0.1:4280"}, Forbidden: []string{"数据库重置"}}
	write := func(name string, v interface{}) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, "evidence", name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("test_info.json", map[string]interface{}{"test_info": map[string]interface{}{"targets": input.Targets, "forbidden_actions": input.Forbidden, "write_authorized": false}})
	write("run-state.json", Summary{Saved: []string{"PT_WEB_03"}, Pending: []string{"PT_WEB_02"}, Status: "blocked"})
	seen := []string{}
	r := &Runner{History: func(context.Context, string, string) ([]*mcp.ToolExecution, error) { return nil, nil }}
	r.Call = func(_ context.Context, name string, a map[string]interface{}) (*mcp.ToolExecution, error) {
		switch a["mode"] {
		case "init":
			t.Fatal("resume created another run")
		case "list":
			return fixtureExecution(name, map[string]interface{}{"execution_order": []interface{}{"PT_WEB_03", "PT_WEB_02", "PT_WEB_AUTH_17", "PT_WEB_AUTH_18"}}), nil
		case "show":
			seen = append(seen, a["case_id"].(string))
			return nil, fmt.Errorf("offline gap")
		case "save_info":
			return fixtureExecution(name, map[string]interface{}{"current_time_utc": "2026-10-12T01:00:00Z"}), nil
		case "build", "check":
			return fixtureExecution(name, map[string]interface{}{"artifact_status": "草稿"}), nil
		}
		return nil, fmt.Errorf("unexpected tool")
	}
	sum, err := r.Run(context.Background(), input)
	if err != nil || len(seen) != 1 || seen[0] != "PT_WEB_AUTH_18" || !contains(sum.Pending, "PT_WEB_AUTH_17") || !contains(sum.Saved, "PT_WEB_03") {
		t.Fatalf("unsafe resume: %+v %v %v", sum, seen, err)
	}
	if !r.budget.Stopped || !r.budget.NMapUsed || r.budget.Attempts != 30 {
		t.Fatal("legacy budgets reset")
	}
	input.WriteAuthorized = true
	if _, err = (&Runner{History: r.History}).Run(context.Background(), input); err == nil {
		t.Fatal("resume expanded authorization")
	}
}
