package banma

import (
	"fmt"
	"sort"
	"strings"
)

// payload binds the handoff's small judgment to platform-owned execution data.
// The model never creates UUIDs, native paths, tool statuses or provenance.
func (r *Runner) payload(d Decision, g map[string]interface{}) (map[string]interface{}, error) {
	checks := make([]Check, 0, len(d.Checks))
	for _, check := range d.Checks {
		if check.Result == "中断" && d.Interruption == "" {
			d.Gaps = append(d.Gaps, "未完成且无真实环境故障依据："+check.Ref)
			continue
		}
		checks = append(checks, check)
	}
	d.Checks = checks
	limitations := d.Gaps
	if limitations == nil {
		limitations = []string{}
	}
	hasFailure := false
	for _, check := range d.Checks {
		if check.Result == "失败" {
			hasFailure = true
		}
	}
	if len(d.Gaps) > 0 && !hasFailure {
		return nil, fmt.Errorf("coverage incomplete: %s", strings.Join(d.Gaps, "; "))
	}

	c, _ := g["case"].(map[string]interface{})
	cid, _ := c["id"].(string)
	refs := map[string]bool{"required": true, "conditional": true}
	for i := range stringList(c["steps"]) {
		refs[fmt.Sprintf("steps[%d]", i)] = true
	}
	seen := map[string]bool{}
	scopes := []interface{}{}
	judgments := []interface{}{}
	observations := []interface{}{}
	operations := []interface{}{}
	evidence := []interface{}{}
	memberships := map[int][]string{}
	eids := map[int][]string{}
	used := map[int]bool{}
	for _, check := range d.Checks {
		for _, idx := range check.Evidence {
			used[idx] = true
		}
	}
	for _, idx := range d.RecoveryEvidence {
		used[idx] = true
	}
	for i, e := range r.captures {
		if !used[i] {
			continue
		}
		if e == nil || e.Result == nil || strings.Contains(e.ToolName, "file") || strings.HasPrefix(e.ToolName, "banma_") {
			continue
		}
		if e.Status != "completed" && e.Status != "failed" && e.Status != "blocked" && e.Status != "hard_timeout" {
			return nil, fmt.Errorf("operation still running")
		}
		if len(e.Result.NativeFiles) == 0 {
			id := fmt.Sprintf("E%d", len(evidence)+1)
			eids[i] = []string{id}
			evidence = append(evidence, map[string]interface{}{
				"evidence_id":   id,
				"source_type":   "执行记录导出",
				"source_ref":    e.ID,
				"coverage":      "实际工具执行记录;不能用摘要代替必要网络原文",
				"provenance":    map[string]interface{}{"execution_id": e.ID, "tool_name": e.ToolName},
			})
		} else {
			for _, f := range e.Result.NativeFiles {
				id := fmt.Sprintf("E%d", len(evidence)+1)
				eids[i] = append(eids[i], id)
				evidence = append(evidence, map[string]interface{}{
					"evidence_id":   id,
					"source_type":   "原始文件",
					"source_ref":    e.ID,
					"source_path":   f.Path,
					"coverage":      "本项实际采集原文",
					"provenance":    map[string]interface{}{"execution_id": e.ID, "tool_name": e.ToolName, "sha256": f.SHA256},
				})
			}
		}
	}
	result := "通过"
	for n, check := range d.Checks {
		if !refs[check.Ref] || seen[check.Ref] || check.Reason == "" || len(check.Evidence) == 0 {
			return nil, fmt.Errorf("missing or invalid check reference %s", check.Ref)
		}
		seen[check.Ref] = true
		if check.Result != "通过" && check.Result != "失败" && check.Result != "中断" {
			return nil, fmt.Errorf("invalid security result")
		}
		if check.Result == "失败" {
			result = "失败"
		} else if check.Result == "中断" && result != "失败" {
			result = "中断"
		}
		sid := fmt.Sprintf("S%d", n+1)
		obs := []string{}
		ev := []string{}
		for _, idx := range check.Evidence {
			if idx < 0 || idx >= len(r.captures) || len(eids[idx]) == 0 {
				return nil, fmt.Errorf("observation refers to missing operation")
			}
			if check.Result != "中断" && r.captures[idx].Status != "completed" {
				return nil, fmt.Errorf("successful judgment lacks completed operation")
			}
			memberships[idx] = append(memberships[idx], sid)
			oid := fmt.Sprintf("V%d", len(observations)+1)
			obs = append(obs, oid)
			ev = append(ev, eids[idx]...)
			observations = append(observations, map[string]interface{}{"observation_id": oid, "operation_id": fmt.Sprintf("O%d", idx+1), "summary": check.Reason, "evidence_ids": eids[idx]})
		}
		scopes = append(scopes, map[string]interface{}{"item_id": sid, "requirement_ref": check.Ref, "must_complete": true, "applicability_reason": "本项原文要求及本轮实测", "baseline_source": "cases/" + cid + ":" + check.Ref, "planned_checks": []string{check.Ref}})
		judgments = append(judgments, map[string]interface{}{"item_id": sid, "result": check.Result, "reason": check.Reason, "observation_ids": obs, "evidence_ids": ev})
	}
	if len(seen) != len(refs) {
		if !hasFailure {
			return nil, fmt.Errorf("handoff did not cover every required/conditional/step reference")
		}
		missing := []string{}
		for ref := range refs {
			if !seen[ref] {
				missing = append(missing, ref)
			}
		}
		sort.Strings(missing)
		for _, ref := range missing {
			limitations = append(limitations, "尚未形成有效结论："+ref)
		}
	}
	for _, idx := range d.RecoveryEvidence {
		if len(memberships[idx]) == 0 {
			memberships[idx] = []string{"S1"}
		}
	}
	for i, e := range r.captures {
		if len(memberships[i]) > 0 {
			operations = append(operations, map[string]interface{}{"operation_id": fmt.Sprintf("O%d", i+1), "item_ids": memberships[i], "tool_name": e.ToolName, "tool_status": e.Status, "execution_id": e.ID, "method_summary": "本轮真实工具操作"})
		}
	}
	recoveryEv := []string{}
	for _, idx := range d.RecoveryEvidence {
		if len(eids[idx]) == 0 {
			return nil, fmt.Errorf("missing recovery evidence")
		}
		recoveryEv = append(recoveryEv, eids[idx]...)
	}
	if d.Recovery == "" {
		if !hasFailure {
			return nil, fmt.Errorf("missing recovery state")
		}
		d.Recovery = "待确认"
		limitations = append(limitations, "恢复状态尚未形成有效结论")
	}
	payload := map[string]interface{}{"scope_items": scopes, "actual_steps": operations, "observations": observations, "evidence": evidence, "item_results": judgments, "result": result, "judgment_reason": "逐条依据用例原文及本项真实观察聚合；失败优先", "coverage_limitations": limitations, "coverage_complete": len(limitations) == 0, "recovery": map[string]interface{}{"status": d.Recovery, "evidence_ids": recoveryEv}, "judgment_method": "code_or_eino", "judgment_review": map[string]interface{}{"approved": true}}
	if result == "失败" {
		level, _ := c["level"].(string)
		severity := map[string]string{"严重": "严重", "高": "高危", "中": "中危", "低": "低危", "信息": "信息"}[level]
		if severity != "" {
			payload["findings"] = []interface{}{map[string]interface{}{"title": c["name"], "severity": severity, "status": "待修复", "impact": "本项实测证实默认安全控制失效，影响限于已测目标与原文支持的范围", "source_refs": []string{cid}}}
		}
	}
	if result == "中断" {
		if d.Interruption == "" {
			return nil, fmt.Errorf("environment interruption needs actual error")
		}
		payload["interruption_reason"] = d.Interruption
		payload["interruption_kind"] = "环境问题"
	}
	return payload, nil
}
func CompleteChecks(g map[string]interface{}, result, reason string, indices []int) []Check {
	c, _ := g["case"].(map[string]interface{})
	out := []Check{{Ref: "required", Result: result, Reason: reason, Evidence: indices}, {Ref: "conditional", Result: "通过", Reason: "已核查本轮授权协议及本项适用分支", Evidence: indices}}
	for i := range stringList(c["steps"]) {
		out = append(out, Check{Ref: fmt.Sprintf("steps[%d]", i), Result: result, Reason: reason, Evidence: indices})
	}
	return out
}
