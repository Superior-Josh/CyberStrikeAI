package banma

import (
	"context"
	"cyberstrike-ai/internal/mcp"
	"net/url"
	"strings"
)

func PlaintextFormDecision(g map[string]interface{}, records []*mcp.ToolExecution) (Decision, bool, error) {
	c, _ := g["case"].(map[string]interface{})
	if c["id"] != "PT_WEB_12" {
		return Decision{}, false, nil
	}
	for index, record := range records {
		if record == nil || record.ToolName != "http-framework-test" || record.Status != "completed" || record.Result == nil || record.Result.IsError {
			continue
		}
		for _, ref := range record.Result.NativeFiles {
			single := *record
			result := *record.Result
			result.NativeFiles = []mcp.NativeFileRef{ref}
			single.Result = &result
			capture, err := ReadCapture(&single)
			if err != nil {
				return Decision{}, true, err
			}
			base, err := url.Parse(capture.URL)
			if err != nil || base.Scheme != "http" || capture.Status != 200 {
				continue
			}
			_, action, err := formFields(capture.Body)
			if err != nil {
				continue
			}
			rel, err := url.Parse(action)
			if err == nil && base.ResolveReference(rel).Scheme == "http" {
				return Decision{Method: "code", Checks: []Check{{Ref: "steps[0]", Result: "失败", Reason: "授权HTTP入口实际提供含用户名与口令字段的明文认证表单；按本项原文基线直接失败，未额外提交真实秘密", Evidence: []int{index}}}, Gaps: []string{"其余TLS协议/套件/证书及已触发链路尚待核验"}, Recovery: "未涉及"}, true, nil
			}
		}
	}
	return Decision{}, false, nil
}

// The case explicitly treats an HTTP authentication form as a failure without
// sending credentials. Preserve that fact while Eino examines remaining TLS gaps.
func (r *Runner) observePlaintextLoginForm(ctx context.Context, in Input) (Decision, bool, error) {
	if len(in.Targets) != 1 {
		return Decision{}, false, nil
	}
	target := in.Targets[0]
	for hop := 0; hop < 4; hop++ {
		record, err := r.request(ctx, "PT_WEB_12", target, "GET", nil, "")
		if err != nil {
			return Decision{}, true, err
		}
		capture, err := ReadCapture(record)
		if err != nil {
			return Decision{}, true, err
		}
		decision, found, err := PlaintextFormDecision(map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_12"}}, r.captures)
		if err != nil {
			return Decision{}, true, err
		}
		if found {
			r.codeDecision = &decision
			return Decision{}, false, nil
		}
		if capture.Status < 300 || capture.Status >= 400 {
			return Decision{}, false, nil
		}
		target, err = captureLocation(capture, target)
		if err != nil {
			return Decision{}, false, nil
		}
		if strings.TrimSpace(target) == "" {
			return Decision{}, false, nil
		}
	}
	return Decision{}, false, nil
}
