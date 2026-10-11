package banma

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/mcp"
)

type Budget struct {
	mu       sync.Mutex
	Attempts int
	Max      int
	Window   time.Duration
	Started  time.Time
	Stopped  bool
	CodeLoop bool
	Handoff  bool
	NMapUsed bool
}

func (r *Runner) checkOperation(name string, args map[string]interface{}) *mcp.ToolResult {
	deny := func(reason string) *mcp.ToolResult {
		b, _ := json.Marshal(map[string]interface{}{"ok": false, "error_code": "AUTHORIZATION_BOUNDARY", "reason": reason})
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}, IsError: true, Blocked: true}
	}
	if name == "banma_pentest_run_cases" || name == "banma_report" {
		r.budget.mu.Lock()
		handoff := r.budget.Handoff
		r.budget.mu.Unlock()
		if handoff {
			return deny("单项Eino交回观察及判断，保存和报告仅由代码控制器调用")
		}
		return nil
	}
	// Free commands cannot enforce shared HTTP counters or per-hop destinations.
	short := name
	if i := strings.LastIndex(short, "::"); i >= 0 {
		short = short[i+2:]
	}
	if short == "read_file" || short == "ls" || short == "glob" || short == "grep" {
		for _, key := range []string{"file_path", "path", "directory", "root_dir"} {
			path := toString(args[key])
			if path == "" {
				continue
			}
			absolute, err := filepath.Abs(path)
			if err != nil {
				return deny("文件路径无效")
			}
			if strings.Contains(absolute, string(filepath.Separator)+"reports"+string(filepath.Separator)) && !strings.HasPrefix(absolute, r.RunDir+string(filepath.Separator)) {
				return deny("不得读取其他轮次报告/原文补证")
			}
		}
	}
	if short == "exec" || short == "execute" || short == "execute-python-script" || short == "execute-python-code" || short == "write_file" || short == "edit_file" {
		return deny("本轮固定任务使用项目网络工具，不能以自由脚本绕过预算或原文采集")
	}
	u, _ := url.Parse(strings.TrimSpace(toString(args["url"])))
	if u != nil && strings.Contains(strings.ToLower(u.Path), "setup.php") && strings.EqualFold(toString(args["method"]), "POST") {
		return deny("禁止数据库重置")
	}
	if name == "nmap" {
		local := true
		for _, raw := range r.input.Targets {
			u, _ := url.Parse(raw)
			if u == nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
				local = false
			}
		}
		if local {
			r.budget.mu.Lock()
			used := r.budget.NMapUsed
			r.budget.NMapUsed = true
			r.budget.mu.Unlock()
			if used {
				return deny("本机nmap已尝试，不反复排查/重试，需用等效能力或保留缺口")
			}
		}

		target := toString(args["target"])
		ports := toString(args["ports"])
		allowed := false
		for _, raw := range r.input.Targets {
			u, _ := url.Parse(raw)
			if u != nil && target == u.Hostname() && ports == u.Port() && ports != "" {
				allowed = true
			}
		}
		if !allowed {
			return deny("端口扫描仅限本轮明确授权的主机和端口")
		}
	}
	if name == "katana" || name == "httpx" || name == "nikto" || name == "nuclei" {
		target := toString(args["url"])
		if target == "" {
			target = toString(args["target"])
		}
		u, err := url.Parse(target)
		allowed := false
		for _, raw := range r.input.Targets {
			a, _ := url.Parse(raw)
			if err == nil && u != nil && a != nil && u.Scheme == a.Scheme && u.Host == a.Host {
				allowed = true
			}
		}
		if !allowed {
			return deny("扫描器目的地必须与本轮授权端点一致")
		}
		if toString(args["additional_args"]) != "" {
			return deny("扩展扫描参数须由代码核对，不接受自由附加参数")
		}
	}
	if name == "http-framework-test" {
		u, err := url.Parse(toString(args["url"]))
		method := strings.ToUpper(toString(args["method"]))
		if err == nil && u != nil && strings.Contains(strings.ToLower(u.Path), "security.php") && (method != "GET" && method != "HEAD" || u.Query().Has("security") || u.Query().Has("seclev_submit")) {
			return deny("禁止修改DVWA安全等级，不因允许业务写入而豁免")
		}
	}
	if name != "http-framework-test" || !strings.EqualFold(toString(args["method"]), "POST") {
		return nil
	}
	if repeat, ok := args["repeat"].(float64); ok && repeat > 1 {
		return deny("重复候选及窗口必须由代码逐次执行，不能批次绕过共享计数")
	}
	body, _ := url.ParseQuery(toString(args["data"]))
	if !body.Has("password") {
		var object map[string]interface{}
		if json.Unmarshal([]byte(toString(args["data"])), &object) == nil {
			if password, ok := object["password"].(string); ok {
				body.Set("password", password)
			}
		}
	}
	if !body.Has("password") {
		return nil
	}
	if body.Get("password") == r.input.Password && r.input.Password != "" {
		return nil
	}
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	if !r.budget.CodeLoop {
		return deny("口令候选的共享计数和窗口由代码执行；Eino只补入口/限制/恢复语义")
	}
	if r.budget.Stopped || r.budget.Attempts >= r.budget.Max || (!r.budget.Started.IsZero() && time.Since(r.budget.Started) > r.budget.Window) {
		return deny("共享候选预算或停止条件已到达")
	}
	if r.budget.Started.IsZero() {
		r.budget.Started = time.Now()
	}
	r.budget.Attempts++
	return nil
}
func toString(v interface{}) string { s, _ := v.(string); return s }

// Canonical arguments are assigned before the MCP execution record is created.
func (r *Runner) prepareArguments(name string, args map[string]interface{}) map[string]interface{} {
	copy := map[string]interface{}{}
	for k, v := range args {
		copy[k] = v
	}
	if name == "http-framework-test" && r.currentCase != "" {
		r.budget.mu.Lock()
		r.sequence++
		n := r.sequence
		r.budget.mu.Unlock()
		copy["capture_file"] = filepath.Join(r.RunDir, "evidence", "raw", r.currentCase, fmt.Sprintf("capture-%06d.json", n))
		copy["follow_redirects"] = false
	}
	return copy
}
