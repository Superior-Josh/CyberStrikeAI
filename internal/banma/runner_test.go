package banma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"
)

func fixtureExecution(name string, body interface{}) *mcp.ToolExecution {
	b, _ := json.Marshal(body)
	return &mcp.ToolExecution{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", time.Now().UnixNano()%1000000000000), ToolName: name, Status: "completed", Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}}}
}
func TestLoopContinuesAllCasesAfterHandoffOrSaveFailures(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "evidence"), 0700)
	order := []interface{}{}
	for i := 1; i <= 18; i++ {
		order = append(order, fmt.Sprintf("PT_WEB_%02d", i))
	}
	for i := 1; i <= 26; i++ {
		order = append(order, fmt.Sprintf("PT_WEB_AUTH_%02d", i))
	}
	seen := []string{}
	r := &Runner{}
	r.Call = func(ctx context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
		switch args["mode"] {
		case "init":
			return fixtureExecution(name, map[string]interface{}{"ok": true, "run_dir": dir}), nil
		case "list":
			return fixtureExecution(name, map[string]interface{}{"ok": true, "execution_order": order}), nil
		case "show":
			cid := args["case_id"].(string)
			seen = append(seen, cid)
			return fixtureExecution(name, map[string]interface{}{"ok": true, "case": map[string]interface{}{"id": cid, "steps": []interface{}{}}, "context": map[string]interface{}{}}), nil
		case "save_info":
			return fixtureExecution(name, map[string]interface{}{"ok": true, "current_time_utc": time.Now().UTC().Format(time.RFC3339Nano)}), nil
		case "build", "check":
			return fixtureExecution(name, map[string]interface{}{"ok": true, "artifact_status": "草稿"}), nil
		}
		return nil, errors.New("offline unavailable tool")
	}
	r.Handoff = func(context.Context, map[string]interface{}) (Decision, []*mcp.ToolExecution, error) {
		return Decision{}, nil, errors.New("offline handoff failure")
	}
	sum, err := r.Run(context.Background(), Input{Targets: []string{"http://127.0.0.1:4280"}})
	if err != nil || len(seen) != 44 || len(sum.Pending) != 44 || len(sum.Saved) != 0 || sum.Status != "blocked" {
		t.Fatalf("loop skipped cases or invented results: %v %+v %d", err, sum, len(seen))
	}
}
func TestCancellationDoesNotBuildReportOrStartNextCase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "evidence"), 0700)
	r := &Runner{}
	reports := 0
	r.Call = func(ctx context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
		if name == "banma_report" {
			reports++
		}
		switch args["mode"] {
		case "init":
			return fixtureExecution(name, map[string]interface{}{"run_dir": dir}), nil
		case "list":
			return fixtureExecution(name, map[string]interface{}{"execution_order": []string{"PT_WEB_02", "PT_WEB_05"}}), nil
		case "show":
			cancel()
			return fixtureExecution(name, map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_02"}}), nil
		}
		return nil, ctx.Err()
	}
	sum, err := r.Run(ctx, Input{Targets: []string{"http://127.0.0.1:4280"}})
	if !errors.Is(err, context.Canceled) || sum.Status != "cancelled" || reports != 0 || len(sum.Pending) != 2 {
		t.Fatalf("cancelled run resumed: %+v %v", sum, err)
	}
}
func TestBudgetSurvivesHandoffAndBlocksExtraCandidates(t *testing.T) {
	r := &Runner{input: Input{Password: "known"}, budget: Budget{Max: 2, Window: time.Minute, CodeLoop: true}}
	args := map[string]interface{}{"url": "http://127.0.0.1:4280/login.php", "method": "POST", "data": "username=a&password=wrong"}
	for i := 0; i < 2; i++ {
		if r.checkOperation("http-framework-test", args) != nil {
			t.Fatal("approved code sample rejected")
		}
	}
	if r.checkOperation("http-framework-test", args) == nil {
		t.Fatal("candidate budget exceeded")
	}
	r.budget.CodeLoop = false
	if r.checkOperation("http-framework-test", args) == nil {
		t.Fatal("Eino repeated candidates")
	}
	if r.checkOperation("exec", map[string]interface{}{"command": "curl target"}) == nil {
		t.Fatal("free command bypass")
	}
}
func TestPayloadRejectsMissingCoverageAndForeignObservations(t *testing.T) {
	r := &Runner{captures: []*mcp.ToolExecution{fixtureExecution("scanner", map[string]string{"output": "OFFLINE"})}}
	guide := map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_03", "steps": []interface{}{"normal and error comparison"}}}
	d := Decision{Checks: []Check{{Ref: "required", Result: "通过", Reason: "fixture", Evidence: []int{0}}}, Recovery: "未涉及"}
	if _, err := r.payload(d, guide); err == nil {
		t.Fatal("missing clauses accepted")
	}
	d.Checks = CompleteChecks(guide, "失败", "fixture", []int{1})
	if _, err := r.payload(d, guide); err == nil {
		t.Fatal("foreign observation accepted")
	}
	d.Checks = CompleteChecks(guide, "失败", "fixture", []int{0})
	p, err := r.payload(d, guide)
	if err != nil || p["result"] != "失败" {
		t.Fatal(err)
	}
}

func TestReportRepairUsesBuildPathWithoutTargetRequests(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "evidence"), 0700)
	r := &Runner{}
	calls := 0
	r.Call = func(ctx context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
		calls++
		if name != "banma_report" && name != "banma_pentest_run_cases" {
			t.Fatal("report repair sent a target request")
		}
		switch args["mode"] {
		case "list":
			return fixtureExecution(name, map[string]interface{}{"saved": []string{"PT_WEB_03"}, "pending": []string{}}), nil
		case "build":
			return fixtureExecution(name, map[string]interface{}{"report_path": filepath.Join(dir, "report.md"), "artifact_status": "草稿"}), nil
		case "check":
			if args["report_file"] != filepath.Join(dir, "report.md") {
				t.Fatal("lost build report_path")
			}
			return fixtureExecution(name, map[string]interface{}{"check_passed": true, "artifact_status": "草稿"}), nil
		default:
			t.Fatal("report repair repeated init, target steps or changed ended_at")
			return nil, nil
		}
	}
	sum, err := r.Run(context.Background(), Input{ReportRunDir: dir})
	if err != nil || sum.Status != "draft" || calls != 4 {
		t.Fatalf("repair failed %+v %v %d", sum, err, calls)
	}
}

func TestDecisionExtractsJSONWithoutAcceptingEmptyOrInventedCompletion(t *testing.T) {
	raw := "An explanation before JSON.\n```json\n{\"checks\":[{\"ref\":\"required\",\"result\":\"失败\",\"reason\":\"observed\",\"evidence\":[0]}],\"gaps\":[\"missing runtime\"],\"recovery\":\"未涉及\"}\n```"
	d, err := ParseDecision(raw)
	if err != nil || len(d.Checks) != 1 || len(d.Gaps) != 1 {
		t.Fatal("transport prefix broke contract", err)
	}
	if _, err := ParseDecision(`{"completed":true}`); err == nil {
		t.Fatal("generic completed flag accepted")
	}
}

func TestConfirmedFailureCanBeRetainedWithoutDeclaringCoverageComplete(t *testing.T) {
	r := &Runner{captures: []*mcp.ToolExecution{fixtureExecution("http-framework-test", map[string]string{"output": "offline fixture"})}}
	guide := map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_01", "steps": []interface{}{"baseline"}}}
	d := Decision{Checks: CompleteChecks(guide, "失败", "fixture only", []int{0}), Gaps: []string{"other required branch unknown"}, Recovery: "未涉及"}
	value, err := r.payload(d, guide)
	if err != nil || value["result"] != "失败" || value["coverage_complete"] != false {
		t.Fatal("failure was lost or incomplete coverage concealed", err)
	}
}

func TestLocalNmapIsNotRetriedAfterItsSingleProbe(t *testing.T) {
	r := &Runner{input: Input{Targets: []string{"http://127.0.0.1:4280"}}}
	args := map[string]interface{}{"target": "127.0.0.1", "ports": "4280", "scan_type": "-sT"}
	if r.checkOperation("nmap", args) != nil {
		t.Fatal("first allowed scope probe rejected")
	}
	args["scan_type"] = "-sT -sV --script ssl-cert"
	if r.checkOperation("nmap", args) == nil {
		t.Fatal("system-interrupted local nmap can be repeatedly retried")
	}
}

func TestPayloadDoesNotIncludeUnreferencedCaptureSources(t *testing.T) {
	r := &Runner{captures: []*mcp.ToolExecution{fixtureExecution("http-framework-test", map[string]string{"output": "used"}), fixtureExecution("http-framework-test", map[string]string{"output": "unused"})}}
	g := map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_07", "steps": []interface{}{}}}
	d := Decision{Checks: CompleteChecks(g, "通过", "fixture", []int{0}), Recovery: "未涉及"}
	p, err := r.payload(d, g)
	if err != nil || len(p["evidence"].([]interface{})) != 1 || len(p["actual_steps"].([]interface{})) != 1 {
		t.Fatal("extra source without operation binding", err)
	}
	d.Recovery = "已恢复"
	d.RecoveryEvidence = []int{1}
	p, err = r.payload(d, g)
	if err != nil || len(p["evidence"].([]interface{})) != 2 || len(p["actual_steps"].([]interface{})) != 2 {
		t.Fatal("recovery source lost its operation binding", err)
	}
}
