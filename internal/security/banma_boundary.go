package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/mcp"
)

var forbiddenBanmaResource = regexp.MustCompile(`(?i)(\.git(?:[/"?]|$)|\.svn(?:[/"?]|$)|\.env(?:[./?"&]|$)|(?:^|/)web\.config|(?:^|/)config(?:\.inc)?\.(?:php|ini|yaml|yml|json)|(?:^|/)\.htaccess|(?:^|/)backup\.(?:sql|zip)|view_source|show_source)`)

func decodeBoundary(value string) string {
	for i := 0; i < 4; i++ {
		next, err := url.QueryUnescape(value)
		if err != nil || next == value {
			break
		}
		value = next
	}
	return strings.ToLower(strings.ReplaceAll(value, "\\", "/"))
}
func sameBanmaHost(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	loop := func(s string) bool { return s == "localhost" || s == "127.0.0.1" || s == "::1" }
	return a == b || (loop(a) && loop(b))
}
func effectivePort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// Checks the concrete calls involved in this incident. It is not an OS/network sandbox.
func (e *Executor) checkBanmaCall(ctx context.Context, name string, args map[string]interface{}) *mcp.ToolResult {
	if blocked := mcp.CheckBanmaOperation(ctx, name, args); blocked != nil {
		return blocked
	}
	if e.mcpServer == nil {
		return nil
	}
	init, err := e.mcpServer.LatestBanmaInit(mcp.MCPConversationIDFromContext(ctx))
	if err != nil {
		return banmaFailure("BOUNDARY_UNAVAILABLE", "test_info", "无法取得本轮授权")
	}
	if init == nil {
		return nil
	}
	payload, ok := init.Arguments["payload"].(map[string]interface{})
	if !ok {
		return banmaFailure("BOUNDARY_UNAVAILABLE", "test_info", "初始化授权无效")
	}
	info, ok := payload["test_info"].(map[string]interface{})
	if !ok {
		return banmaFailure("BOUNDARY_UNAVAILABLE", "test_info", "初始化授权无效")
	}
	if name == "banma_report" {
		var initialized struct {
			RunDir string `json:"run_dir"`
		}
		if init.Result == nil || json.Unmarshal([]byte(mcp.ToolResultPlainText(init.Result)), &initialized) != nil || initialized.RunDir != args["run_dir"] {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "run_dir", "报告仅允许本会话真实init目录")
		}
	}
	if strings.HasPrefix(name, "banma_") || name == "wait_tool_execution" || name == "get_tool_execution" || name == "cancel_tool_execution" {
		return nil
	}
	data, _ := json.Marshal(args)
	text := decodeBoundary(string(data))
	method := strings.ToUpper(fmt.Sprint(args["method"]))
	if method == "<NIL>" || method == "" {
		method = "GET"
	}
	if forbiddenBanmaResource.MatchString(text) && !(name == "http-framework-test" && method == "HEAD") {
		return banmaFailure("AUTHORIZATION_BOUNDARY", "arguments", "本轮禁止读取源码/配置；不能用GET、扫描器或脚本绕过")
	}
	if regexp.MustCompile(`(?i)\bfind\s+/(?:\s|["'])`).MatchString(text) || strings.Contains(text, "cat /etc") || strings.Contains(text, "docker exec") || strings.Contains(text, "nerdctl exec") || strings.Contains(text, "dvwa_src") {
		return banmaFailure("AUTHORIZATION_BOUNDARY", "arguments", "禁止本机白盒搜索、容器或部署读取")
	}
	short := strings.TrimPrefix(name, "eino_fs::")
	if short == "read_file" || short == "write_file" || short == "edit_file" || short == "ls" || short == "glob" || short == "grep" {
		root := os.Getenv("CYBERSTRIKE_ROOT")
		if root == "" {
			root = "/Users/banma-josh/project/CyberStrikeAI"
		}
		for _, key := range []string{"file_path", "path", "directory", "root_dir"} {
			value, ok := args[key].(string)
			if !ok || value == "" {
				continue
			}
			absolute, err := filepath.Abs(value)
			if err != nil {
				return banmaFailure("AUTHORIZATION_BOUNDARY", key, "路径无效")
			}
			if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
				absolute = resolved
			}
			allowed := false
			for _, dir := range []string{"cases", "templates", "tools", "roles", "reports", "tmp/workspace/conversations/" + mcp.MCPConversationIDFromContext(ctx), "data/conversation_artifacts/" + mcp.MCPConversationIDFromContext(ctx)} {
				base := filepath.Join(root, dir)
				if absolute == base || strings.HasPrefix(absolute, base+string(os.PathSeparator)) {
					allowed = true
				}
			}
			if !allowed {
				return banmaFailure("AUTHORIZATION_BOUNDARY", key, "只允许本项目指导/模板/本轮原文及采集工作目录，不读取靶机内部资料")
			}
			if short == "write_file" || short == "edit_file" {
				if !strings.Contains(absolute, "/evidence/raw/") && !strings.Contains(absolute, "/tmp/workspace/conversations/") {
					return banmaFailure("AUTHORIZATION_BOUNDARY", key, "结果及报告只能通过辅助接口写入")
				}
			}
		}
	}
	if name == "http-framework-test" {
		var initialized struct {
			RunDir string `json:"run_dir"`
		}
		if json.Unmarshal([]byte(mcp.ToolResultPlainText(init.Result)), &initialized) != nil || initialized.RunDir == "" {
			return banmaFailure("BOUNDARY_UNAVAILABLE", "run_dir", "初始化目录缺失")
		}
		capture, _ := args["capture_file"].(string)
		absolute, err := filepath.Abs(capture)
		rawDir := filepath.Join(initialized.RunDir, "evidence", "raw")
		if capture == "" || err != nil || !strings.HasPrefix(absolute, rawDir+string(os.PathSeparator)) {
			return banmaFailure("CAPTURE_PATH_REQUIRED", "capture_file", "原生capture_file必须使用本轮raw_dir内唯一绝对路径")
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err == nil && !strings.HasPrefix(parent, rawDir) {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "capture_file", "采集目录不能经符号链接越界")
		}
		if _, err := os.Lstat(absolute); err == nil {
			return banmaFailure("CAPTURE_ALREADY_EXISTS", "capture_file", "该原文路径已存在，换唯一文件名，不覆盖此前原文")
		}
		requested, err := url.Parse(fmt.Sprint(args["url"]))
		if err != nil || requested.Hostname() == "" {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "url", "需要实际授权URL")
		}
		targetData, _ := json.Marshal(info["targets"])
		var targets []string
		_ = json.Unmarshal(targetData, &targets)
		permitted := false
		for _, target := range targets {
			u, err := url.Parse(target)
			if err == nil && sameBanmaHost(u.Hostname(), requested.Hostname()) && effectivePort(u) == effectivePort(requested) && requested.Scheme == u.Scheme {
				permitted = true
			}
		}
		if !permitted {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "url", "目标主机、端口或协议不在本轮授权内")
		}
		if args["follow_redirects"] == true {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "follow_redirects", "逐次核对Location后请求，不自动跟随未核对目的地")
		}
		if strings.Contains(text, "create_db") || strings.Contains(text, "password_new") || (strings.Contains(requested.Path, "security.php") && method != "GET" && method != "HEAD") {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "arguments", "禁止数据库重置、安全等级变更或当前未获准的业务变更")
		}
		if writable, ok := info["write_authorized"].(bool); ok && !writable {
			if method == "PUT" || method == "PATCH" || method == "DELETE" || (method == "POST" && !strings.HasSuffix(requested.Path, "login.php") && !strings.HasSuffix(requested.Path, "/auth/login")) {
				return banmaFailure("AUTHORIZATION_BOUNDARY", "method", "本轮只读，不能自行执行业务写入")
			}
		}
	}
	if name == "nikto" || name == "dirsearch" || name == "dirb" || name == "jaeles" || name == "trivy" {
		return banmaFailure("AUTHORIZATION_BOUNDARY", "tool", "本轮黑盒禁止内部资料读取；此工具默认扫描无法确认符合该限制，使用获准HTTP检查或明确模板，不自动扩大范围")
	}
	if name == "nuclei" {
		template, _ := args["template"].(string)
		if template == "" {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "template", "先核对明确模板文件，不能只按tags批量运行可能读取配置或猜口令的模板")
		}
		if strings.Contains(template, ",") {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "template", "每次核对一个明确模板文件")
		}
		raw, err := os.ReadFile(template)
		if err != nil {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "template", "需要可读的明确扫描器模板")
		}
		code := decodeBoundary(string(raw))
		if forbiddenBanmaResource.MatchString(code) || strings.Contains(code, "interactsh") || strings.Contains(code, "default-login") || strings.Contains(code, "headless:") || strings.Contains(code, "javascript:") || strings.Contains(code, "code:") || strings.Contains(code, "workflow") {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "template", "模板包含禁止读取、带外访问、额外凭据尝试或不可核对执行")
		}
	}
	return nil
}

func (e *Executor) BanmaBoundaryCheck(ctx context.Context, name string, args map[string]interface{}) *mcp.ToolResult {
	return e.checkBanmaCall(ctx, name, args)
}
