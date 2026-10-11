package banma

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// Continuation keeps the frozen checklist and never retries an attempted case.
// Legacy runs did not persist candidate budgets; uncertainty closes that budget.
func (r *Runner) restoreRun(input Input, sum *Summary) error {
	if input.ReportRunDir != "" || len(input.CaseIDs) != 0 {
		return fmt.Errorf("resume cannot change checklist or repair mode")
	}
	raw, err := os.ReadFile(filepath.Join(r.RunDir, "evidence/test_info.json"))
	if err != nil {
		return err
	}
	var frozen struct {
		TestInfo struct {
			Targets         []string `json:"targets"`
			Forbidden       []string `json:"forbidden_actions"`
			WriteAuthorized bool     `json:"write_authorized"`
		} `json:"test_info"`
	}
	if err = json.Unmarshal(raw, &frozen); err != nil {
		return err
	}
	if !reflect.DeepEqual(frozen.TestInfo.Targets, input.Targets) || !reflect.DeepEqual(frozen.TestInfo.Forbidden, input.Forbidden) || frozen.TestInfo.WriteAuthorized != input.WriteAuthorized {
		return fmt.Errorf("resume authorization differs from frozen test_info")
	}
	raw, err = os.ReadFile(filepath.Join(r.RunDir, "evidence/run-state.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, sum); err != nil {
		return err
	}
	if sum.Status == "completed" {
		return fmt.Errorf("completed run cannot be resumed")
	}
	if sum.Gaps == nil {
		sum.Gaps = map[string]string{}
	}
	if sum.CaseExecutionIDs == nil {
		sum.CaseExecutionIDs = map[string][]string{}
	}
	for cid := range sum.CaseExecutionIDs {
		if !contains(sum.Attempted, cid) {
			sum.Attempted = append(sum.Attempted, cid)
		}
	}
	for _, cid := range sum.Saved {
		if !contains(sum.Attempted, cid) {
			sum.Attempted = append(sum.Attempted, cid)
		}
	}
	// A legacy process can die before persisting its current case. Native files
	// identify it without treating an unfinished tool record as completed evidence.
	dirs, err := os.ReadDir(filepath.Join(r.RunDir, "evidence/raw"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, d := range dirs {
		if d.IsDir() && strings.HasPrefix(d.Name(), "PT_WEB_") && !contains(sum.Attempted, d.Name()) {
			cid := d.Name()
			sum.Attempted = append(sum.Attempted, cid)
			if !contains(sum.Pending, cid) {
				sum.Pending = append(sum.Pending, cid)
			}
			sum.Gaps[cid] = "进程退出时执行未收尾；保留原文，不重放未知操作，待同轮只读核验"
		}
	}
	for _, cid := range sum.Attempted {
		if !contains(sum.Saved, cid) && !contains(sum.Pending, cid) {
			sum.Pending = append(sum.Pending, cid)
			sum.Gaps[cid] = "进程退出时执行未收尾；不重放未知操作，待同轮只读核验"
		}
	}
	r.sequence = int(time.Now().UnixMicro()) // retain unique paths across old counters
	r.budget.Attempts = 30
	r.budget.Max = 30
	r.budget.Stopped = true
	r.budget.NMapUsed = true
	sum.RunDir = r.RunDir
	sum.Status = "blocked"
	return r.persist(*sum)
}
