package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/mcp"
)

func banmaFailure(code, field, reason string) *mcp.ToolResult {
	data, _ := json.Marshal(map[string]interface{}{"ok": false, "error_code": code, "field": field, "reason": reason, "retry_hint": "修正真实执行、证据引用或覆盖后重试，不重复状态未知的副作用，不手写原文"})
	return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(data)}}, IsError: true, Blocked: code == "AUTHORIZATION_BOUNDARY" || code == "BOUNDARY_UNAVAILABLE"}
}
func nativeHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (e *Executor) attachNativeFiles(name string, args map[string]interface{}, result *mcp.ToolResult) {
	// Metadata is attached by the executor, not accepted from model input.
	var paths []string
	if name == "http-framework-test" {
		if p, ok := args["capture_file"].(string); ok && p != "" {
			repeat := 1
			if value, ok := args["repeat"].(float64); ok && value > 1 {
				repeat = int(value)
			}
			if value, ok := args["repeat"].(int); ok && value > 1 {
				repeat = value
			}
			if repeat > 1000 {
				return
			}
			for i := 1; i <= repeat; i++ {
				actual := strings.ReplaceAll(p, "{i}", fmt.Sprint(i))
				if repeat > 1 && !strings.Contains(p, "{i}") {
					ext := filepath.Ext(p)
					actual = strings.TrimSuffix(p, ext) + fmt.Sprintf("-%d", i) + ext
				}
				paths = append(paths, actual)
			}
		}
	}
	if name == "nuclei" || name == "nikto" || name == "trivy" {
		raw, _ := args["additional_args"].(string)
		argv := e.parseAdditionalArgs(raw)
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "-o" || argv[i] == "-output" || argv[i] == "--output" {
				paths = append(paths, argv[i+1])
			}
		}
	}
	if name == "banma_pentest_run_cases" && args["mode"] == "save" && !result.IsError {
		paths = append(paths, filepath.Join(fmt.Sprint(args["run_dir"]), "evidence", fmt.Sprint(args["case_id"])+".json"))
	}
	if name == "banma_report" && args["mode"] == "check" && !result.IsError {
		paths = append(paths, filepath.Join(fmt.Sprint(args["run_dir"]), "evidence", "report-check.json"))
	}
	for _, p := range paths {
		absolute, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		stat, err := os.Lstat(absolute)
		if err != nil || !stat.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(absolute)
		if err != nil {
			continue
		}
		result.NativeFiles = append(result.NativeFiles, mcp.NativeFileRef{Path: absolute, SHA256: nativeHash(data)})
	}
}

func (e *Executor) prepareBanmaSave(ctx context.Context, args map[string]interface{}) (map[string]interface{}, *mcp.ToolResult) {
	if !mcp.IsBanmaController(ctx) {
		return nil, banmaFailure("CONTROLLER_REQUIRED", "save", "新路线由代码关联操作并保存；Eino仅交回单项判断")
	}
	// Clone model arguments before binding trusted runtime values.
	data, err := json.Marshal(args)
	if err != nil {
		return nil, banmaFailure("INVALID_INPUT", "payload", "输入格式错误")
	}
	var prepared map[string]interface{}
	_ = json.Unmarshal(data, &prepared)
	payload, ok := prepared["payload"].(map[string]interface{})
	if !ok {
		return nil, banmaFailure("INVALID_INPUT", "payload", "需要对象")
	}
	run, _ := prepared["run_dir"].(string)
	// The helper's path validation is also applied before writing exports.
	root := os.Getenv("CYBERSTRIKE_ROOT")
	if root == "" {
		root = "/Users/banma-josh/project/CyberStrikeAI"
	}
	allowed, err := filepath.EvalSymlinks(filepath.Join(root, "reports"))
	if err != nil {
		return nil, banmaFailure("SOURCE_UNAVAILABLE", "run_dir", "本轮目录不可用")
	}
	resolved, err := filepath.EvalSymlinks(run)
	if err != nil || !strings.HasPrefix(resolved, allowed+string(os.PathSeparator)) {
		return nil, banmaFailure("INVALID_INPUT", "run_dir", "目录越界")
	}
	rawDir := filepath.Join(resolved, "evidence", "raw")
	resolvedRaw, err := filepath.EvalSymlinks(rawDir)
	if err != nil || !strings.HasPrefix(resolvedRaw, resolved+string(os.PathSeparator)) {
		return nil, banmaFailure("INVALID_INPUT", "raw_dir", "原文目录越界")
	}
	conversation := mcp.MCPConversationIDFromContext(ctx)
	if conversation == "" || e.mcpServer == nil {
		return nil, banmaFailure("PROVENANCE_REQUIRED", "execution_id", "需要本轮项目执行上下文")
	}
	currentInit, initErr := e.mcpServer.LatestBanmaInit(conversation)
	if initErr != nil || currentInit == nil {
		return nil, banmaFailure("PROVENANCE_REQUIRED", "run_dir", "需要本轮真实init调用")
	}
	var initialized struct {
		OK     bool   `json:"ok"`
		RunDir string `json:"run_dir"`
	}
	if currentInit.Result == nil || json.Unmarshal([]byte(mcp.ToolResultPlainText(currentInit.Result)), &initialized) != nil || !initialized.OK || initialized.RunDir != run {
		return nil, banmaFailure("PROVENANCE_MISMATCH", "run_dir", "不能复用其他轮次的目录或证据")
	}
	operations, ok := payload["actual_steps"].([]interface{})
	if !ok {
		return nil, banmaFailure("INVALID_INPUT", "actual_steps", "需要操作数组")
	}
	verified := map[string]*mcp.ToolExecution{}
	for _, raw := range operations {
		op, ok := raw.(map[string]interface{})
		if !ok {
			return nil, banmaFailure("INVALID_INPUT", "actual_steps", "操作格式错误")
		}
		id, _ := op["execution_id"].(string)
		record, found := e.mcpServer.GetExecution(id)
		if !found || record.ConversationID != conversation || record.StartTime.Before(currentInit.StartTime) || record.ToolName != op["tool_name"] || record.Status != op["tool_status"] {
			return nil, banmaFailure("PROVENANCE_MISMATCH", "actual_steps.execution_id", "工具名、状态或会话与真实执行不符")
		}
		verified[id] = record
	}
	evidence, ok := payload["evidence"].([]interface{})
	if !ok {
		return nil, banmaFailure("INVALID_INPUT", "evidence", "需要证据数组")
	}
	for _, raw := range evidence {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return nil, banmaFailure("INVALID_INPUT", "evidence", "证据格式错误")
		}
		if item["source_type"] == "输入事实" {
			continue
		}
		id, _ := item["source_ref"].(string)
		record := verified[id]
		if record == nil || record.Result == nil || strings.Contains(record.ToolName, "file") || strings.HasPrefix(record.ToolName, "banma_") {
			return nil, banmaFailure("PROVENANCE_MISMATCH", "evidence.source_ref", "必须引用真实采集执行ID，文件读写/辅助资料不是目标原文")
		}
		var source []byte
		if item["source_type"] == "原始文件" {
			path, _ := item["source_path"].(string)
			absolute, err := filepath.Abs(path)
			if err != nil {
				return nil, banmaFailure("SOURCE_UNAVAILABLE", "source_path", "路径无效")
			}
			for _, native := range record.Result.NativeFiles {
				if native.Path == absolute {
					bytes, err := os.ReadFile(absolute)
					if err == nil && nativeHash(bytes) == native.SHA256 {
						source = bytes
					}
				}
			}
			if len(source) == 0 {
				return nil, banmaFailure("PROVENANCE_MISMATCH", "source_path", "未匹配采集执行原生文件及运行时哈希；不能使用AI摘要或空命中文件")
			}
		} else if item["source_type"] == "执行记录导出" {
			source, _ = json.Marshal(map[string]interface{}{"source": "CyberStrikeAI execution record", "execution_id": record.ID, "tool_name": record.ToolName, "status": record.Status, "arguments": record.Arguments, "result": record.Result})
		} else {
			return nil, banmaFailure("INVALID_INPUT", "source_type", "来源类型无效")
		}
		path := filepath.Join(resolvedRaw, "execution-"+nativeHash(source)+".json")
		if stat, err := os.Lstat(path); err == nil && !stat.Mode().IsRegular() {
			return nil, banmaFailure("INVALID_INPUT", "source_path", "原文导出路径异常")
		}
		if err = os.WriteFile(path, source, 0600); err != nil {
			return nil, banmaFailure("SOURCE_UNAVAILABLE", "source_path", "无法导出真实原文")
		}
		if err = os.Chmod(path, 0600); err != nil {
			return nil, banmaFailure("SOURCE_UNAVAILABLE", "source_path", "原文权限设置失败")
		}
		item["source_path"] = path
		item["provenance"] = map[string]interface{}{"execution_id": record.ID, "tool_name": record.ToolName, "sha256": nativeHash(source)}
	}
	// Provenance is checked here; safety semantics belong to the code runner or
	// its Eino handoff, not a second mandatory model approval.
	payload["judgment_method"] = mcp.BanmaJudgmentMethod(ctx)
	return prepared, nil
}

func (e *Executor) captureBanmaScriptInputs(ctx context.Context, name string, args map[string]interface{}) []mcp.NativeInputRef {
	if name != "exec" || e.mcpServer == nil {
		return nil
	}
	init, err := e.mcpServer.LatestBanmaInit(mcp.MCPConversationIDFromContext(ctx))
	if err != nil || init == nil {
		return nil
	}
	root := os.Getenv("CYBERSTRIKE_ROOT")
	if root == "" {
		root = "/Users/banma-josh/project/CyberStrikeAI"
	}
	workspace := filepath.Join(root, "tmp/workspace/conversations", mcp.MCPConversationIDFromContext(ctx))
	command, _ := args["command"].(string)
	var captured []mcp.NativeInputRef
	for _, arg := range e.parseAdditionalArgs(command) {
		if !strings.HasSuffix(arg, ".py") {
			continue
		}
		path, err := filepath.Abs(arg)
		if err != nil {
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !strings.HasPrefix(resolved, workspace+string(os.PathSeparator)) {
			continue
		}
		data, err := os.ReadFile(resolved)
		if err != nil || len(data) > 100000 {
			continue
		}
		captured = append(captured, mcp.NativeInputRef{Path: resolved, SHA256: nativeHash(data), Text: string(data)})
	}
	return captured
}
