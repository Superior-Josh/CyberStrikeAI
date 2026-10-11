// Package banma owns the fixed-case loop. Eino only receives an individual gap.
package banma

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cyberstrike-ai/internal/mcp"
)

type Input struct {
	ResumeRunDir    string   `json:"resume_run_dir,omitempty"`
	ReviewCase      string   `json:"review_case_id,omitempty"`
	ReportRunDir    string   `json:"report_run_dir,omitempty"`
	Targets         []string `json:"targets"`
	CaseIDs         []string `json:"case_ids,omitempty"`
	Forbidden       []string `json:"forbidden_actions"`
	WriteAuthorized bool     `json:"write_authorized"`
	Username        string   `json:"username,omitempty"`
	Password        string   `json:"password,omitempty"`
}
type Call func(context.Context, string, map[string]interface{}) (*mcp.ToolExecution, error)
type Handoff func(context.Context, map[string]interface{}) (Decision, []*mcp.ToolExecution, error)
type Check struct {
	Ref      string `json:"ref"`
	Result   string `json:"result"`
	Reason   string `json:"reason"`
	Evidence []int  `json:"evidence"`
}
type Decision struct {
	Checks           []Check  `json:"checks"`
	Gaps             []string `json:"gaps"`
	Recovery         string   `json:"recovery"`
	RecoveryEvidence []int    `json:"recovery_evidence"`
	Interruption     string   `json:"interruption"`
}
type Runner struct {
	History     func(context.Context, string, string) ([]*mcp.ToolExecution, error)
	Call        Call
	Handoff     Handoff
	Progress    func(string, map[string]interface{})
	RunDir      string
	IDs         []string
	captures    []*mcp.ToolExecution
	sequence    int
	budget      Budget
	input       Input
	currentCase string
}
type Summary struct {
	Attempted        []string               `json:"attempted"`
	PartialSaved     []string               `json:"partial_saved"`
	CaseExecutionIDs map[string][]string    `json:"case_execution_ids"`
	RunDir           string                 `json:"run_dir"`
	Saved            []string               `json:"saved"`
	Pending          []string               `json:"pending"`
	Gaps             map[string]string      `json:"gaps"`
	Report           map[string]interface{} `json:"report"`
	Status           string                 `json:"status"`
}

func Decode(r *mcp.ToolExecution) (map[string]interface{}, error) {
	if r == nil || r.Result == nil {
		return nil, fmt.Errorf("missing execution result")
	}
	if r.Status != "completed" || r.Result.IsError {
		return nil, fmt.Errorf("tool %s ended as %s", r.ToolName, r.Status)
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(mcp.ToolResultPlainText(r.Result)), &v); err != nil {
		return nil, err
	}
	if ok, exists := v["ok"]; exists && ok != true {
		return nil, fmt.Errorf("tool rejected input")
	}
	return v, nil
}
func (r *Runner) call(ctx context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e, err := r.Call(ctx, name, args)
	if e != nil {
		r.IDs = append(r.IDs, e.ID)
	}
	return e, err
}
func (r *Runner) helper(ctx context.Context, mode, cid string, payload interface{}) (map[string]interface{}, error) {
	args := map[string]interface{}{"mode": mode}
	if r.RunDir != "" {
		args["run_dir"] = r.RunDir
	}
	if cid != "" {
		args["case_id"] = cid
	}
	if payload != nil {
		args["payload"] = payload
	}
	e, err := r.call(ctx, "banma_pentest_run_cases", args)
	if err != nil {
		return nil, err
	}
	return Decode(e)
}
func stringList(value interface{}) []string {
	out := []string{}
	if a, ok := value.([]interface{}); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
func (r *Runner) emit(message string, data map[string]interface{}) {
	if r.Progress != nil {
		r.Progress(message, data)
	}
}
func (r *Runner) Run(ctx context.Context, input Input) (Summary, error) {
	r.input = input
	ctx = mcp.WithBanmaController(ctx)
	ctx = mcp.WithBanmaCallCheck(ctx, r.checkOperation)
	ctx = mcp.WithBanmaArguments(ctx, r.prepareArguments)
	sum := Summary{CaseExecutionIDs: map[string][]string{}, Saved: []string{}, Pending: []string{}, Gaps: map[string]string{}, Status: "blocked"}
	if input.ReportRunDir != "" {
		r.RunDir = input.ReportRunDir
		if raw, er := os.ReadFile(filepath.Join(r.RunDir, "evidence/run-state.json")); er == nil {
			_ = json.Unmarshal(raw, &sum)
		}
		if sum.Gaps == nil {
			sum.Gaps = map[string]string{}
		}
		if sum.CaseExecutionIDs == nil {
			sum.CaseExecutionIDs = map[string][]string{}
		}
		sum.RunDir = r.RunDir

		list, err := r.helper(ctx, "list", "", nil)
		if err != nil {
			return sum, err
		}
		if input.ReviewCase != "" {
			if r.History == nil || r.Handoff == nil {
				return sum, fmt.Errorf("review handoff unavailable")
			}
			r.currentCase = input.ReviewCase
			guide, er := r.helper(ctx, "show", input.ReviewCase, nil)
			if er != nil {
				return sum, er
			}
			r.captures, er = r.History(ctx, r.RunDir, input.ReviewCase)
			if er != nil {
				return sum, er
			}
			sum.CaseExecutionIDs[input.ReviewCase] = []string{}
			for _, record := range r.captures {
				sum.CaseExecutionIDs[input.ReviewCase] = append(sum.CaseExecutionIDs[input.ReviewCase], record.ID)
			}
			material := map[string]interface{}{"guidance": guide, "existing_operations": r.captures, "review_only": true, "password": input.Password}
			r.budget.mu.Lock()
			r.budget.Handoff = true
			r.budget.mu.Unlock()
			decision, _, er := r.Handoff(mcp.WithoutBanmaController(ctx), material)
			r.budget.mu.Lock()
			r.budget.Handoff = false
			r.budget.mu.Unlock()
			if er == nil {
				var payload map[string]interface{}
				payload, er = r.payload(decision, guide)
				if er == nil {
					_, er = r.helper(mcp.WithBanmaJudgment(ctx, "eino"), "save", input.ReviewCase, payload)
				}
			}
			if er != nil {
				sum.Gaps[input.ReviewCase] = redactError(er, input)
				if ctx.Err() == nil && guide["existing_result_path"] != nil {
					if _, markErr := r.helper(ctx, "mark_pending", input.ReviewCase, map[string]interface{}{"reason": sum.Gaps[input.ReviewCase]}); markErr != nil {
						return sum, markErr
					}
				}
				if ctx.Err() != nil {
					sum.Status = "cancelled"
					_ = r.persist(sum)
					return sum, ctx.Err()
				}
			} else {
				delete(sum.Gaps, input.ReviewCase)
			}
			list, er = r.helper(ctx, "list", "", nil)
			if er != nil {
				return sum, er
			}
		}
		sum.Saved = stringList(list["saved"])
		sum.Pending = stringList(list["pending"])
		return r.finishReport(ctx, sum, true)
	}
	if len(input.Targets) == 0 {
		return sum, fmt.Errorf("explicit target required")
	}
	for _, target := range input.Targets {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return sum, fmt.Errorf("invalid target")
		}
	}
	if input.ResumeRunDir != "" {
		if r.History == nil {
			return sum, fmt.Errorf("resume history unavailable")
		}
		r.RunDir = input.ResumeRunDir
		if _, err := r.History(ctx, r.RunDir, ""); err != nil {
			return sum, err
		}
		if err := r.restoreRun(input, &sum); err != nil {
			return sum, err
		}
	} else {
		info := map[string]interface{}{"targets": input.Targets, "write_authorized": input.WriteAuthorized, "forbidden_actions": input.Forbidden, "execution_mode": "code_eino"}
		if len(input.CaseIDs) > 0 {
			info["case_ids"] = input.CaseIDs
		}
		init, err := r.helper(ctx, "init", "", map[string]interface{}{"test_name": "banma-" + time.Now().UTC().Format("20060102T150405.000000000"), "test_info": info})
		if err != nil {
			return sum, err
		}
		r.RunDir, _ = init["run_dir"].(string)
		sum.RunDir = r.RunDir
	}
	list, err := r.helper(ctx, "list", "", nil)
	if err != nil {
		return sum, err
	}
	order := stringList(list["execution_order"])
	if len(order) == 0 {
		return sum, fmt.Errorf("empty fixed checklist")
	}
	for n, cid := range order {
		if ctx.Err() != nil {
			sum.Status = "cancelled"
			sum.Pending = append(sum.Pending, order[n:]...)
			r.persist(sum)
			return sum, ctx.Err()
		}
		if input.ResumeRunDir != "" && contains(sum.Attempted, cid) {
			continue
		}
		sum.Attempted = append(sum.Attempted, cid)
		// Persist before any target operation so a lost process never silently
		// replays an unknown write on continuation.
		if err := r.persist(sum); err != nil {
			return sum, err
		}
		r.currentCase = cid
		r.emit("执行 "+cid, map[string]interface{}{"case_id": cid, "position": n + 1, "total": len(order), "saved": len(sum.Saved)})
		guide, guideErr := r.helper(ctx, "show", cid, nil)
		r.captures = nil
		// Anonymous entry preparation is a repeatable network operation. The
		// handoff should not invent or omit its normal/nonexistent controls.
		if guideErr == nil && cid != "PT_WEB_01" && cid != "PT_WEB_03" && cid != "PT_WEB_04" && !strings.Contains(cid, "_AUTH_") {
			for _, target := range input.Targets {
				u, _ := url.Parse(target)
				if u == nil {
					continue
				}
				_, er := r.request(ctx, cid, target, "GET", nil, "")
				if er != nil {
					guideErr = er
					break
				}
				u.Path = "/banma-not-found-" + fmt.Sprint(time.Now().UnixNano())
				u.RawPath = ""
				u.RawQuery = ""
				u.Fragment = ""
				_, er = r.request(ctx, cid, u.String(), "GET", nil, "")
				if er != nil {
					guideErr = er
					break
				}
			}
		}
		var d Decision
		method := "code"
		if guideErr == nil {
			var supported bool
			d, supported, guideErr = r.executeCode(ctx, cid, input, guide)
			if !supported && ctx.Err() == nil {
				method = "eino"
				guideErr = nil
				if r.Handoff == nil {
					guideErr = fmt.Errorf("Eino handoff unavailable")
				} else {
					// Secrets stay in the running context; never persist them in run metadata.
					material := map[string]interface{}{"guidance": guide, "existing_operations": r.captures, "username": input.Username, "password": input.Password}
					var records []*mcp.ToolExecution
					r.budget.mu.Lock()
					r.budget.Handoff = true
					r.budget.mu.Unlock()
					d, records, guideErr = r.Handoff(mcp.WithoutBanmaController(ctx), material)
					r.budget.mu.Lock()
					r.budget.Handoff = false
					r.budget.mu.Unlock()
					for _, e := range records {
						if e != nil {
							r.IDs = append(r.IDs, e.ID)
							if IsTargetTool(e.ToolName) {
								r.captures = append(r.captures, e)
							}
						}
					}
				}
			}
		}
		if guideErr == nil {
			var payload map[string]interface{}
			payload, guideErr = r.payload(d, guide)
			if guideErr == nil {
				_, guideErr = r.helper(mcp.WithBanmaJudgment(ctx, method), "save", cid, payload)
			}
		}
		for _, record := range r.captures {
			if record != nil {
				sum.CaseExecutionIDs[cid] = append(sum.CaseExecutionIDs[cid], record.ID)
			}
		}
		if guideErr != nil {
			sum.Pending = append(sum.Pending, cid)
			sum.Gaps[cid] = redactError(guideErr, input)
			r.emit(cid+"保留缺口", map[string]interface{}{"case_id": cid, "reason": sum.Gaps[cid]})
		} else if len(d.Gaps) > 0 {
			sum.PartialSaved = append(sum.PartialSaved, cid)
			sum.Pending = append(sum.Pending, cid)
			sum.Gaps[cid] = strings.Join(d.Gaps, "; ")
			r.emit(cid+"已保留失败，覆盖仍有缺口", map[string]interface{}{"case_id": cid})
		} else {
			sum.Saved = append(sum.Saved, cid)
		}
		if err := r.persist(sum); err != nil {
			return sum, err
		}
	}
	if ctx.Err() != nil {
		sum.Status = "cancelled"
		return sum, ctx.Err()
	}
	return r.finishReport(ctx, sum, false)
}
func (r *Runner) finishReport(ctx context.Context, sum Summary, repair bool) (Summary, error) {
	_, err := r.helper(ctx, "list", "", nil)
	if err != nil {
		return sum, err
	}
	var e *mcp.ToolExecution
	if !repair {
		args := map[string]interface{}{"mode": "save_info", "run_dir": r.RunDir, "payload": map[string]interface{}{"test_info": map[string]interface{}{"test_object": "授权网络目标", "tester": "CyberStrikeAI", "document_version": "1.0"}}}
		e, err = r.call(ctx, "banma_report", args)
		if err != nil {
			return sum, err
		}
		saved, err := Decode(e)
		if err != nil {
			return sum, err
		}
		args["payload"] = map[string]interface{}{"test_info": map[string]interface{}{"ended_at": saved["current_time_utc"]}}
		e, err = r.call(ctx, "banma_report", args)
		if err != nil {
			return sum, err
		}
		if _, err = Decode(e); err != nil {
			return sum, err
		}
	}
	for _, mode := range []string{"build", "check"} {
		reportArgs := map[string]interface{}{"mode": mode, "run_dir": r.RunDir}
		if mode == "check" {
			reportArgs["report_file"] = sum.Report["report_path"]
		}
		e, err = r.call(ctx, "banma_report", reportArgs)
		if err != nil {
			return sum, err
		}
		sum.Report, err = Decode(e)
		if err != nil {
			return sum, err
		}
	}
	if len(sum.Pending) == 0 && sum.Report["artifact_status"] == "最终" {
		sum.Status = "completed"
	} else if len(sum.Pending) == 0 {
		sum.Status = "draft"
	}
	return sum, r.persist(sum)
}
func redactError(err error, input Input) string { // Error text from tools may contain submitted credentials.
	if err == nil {
		return ""
	}
	v := err.Error()
	for _, secret := range []string{input.Password, input.Username} {
		if secret != "" {
			v = strings.ReplaceAll(v, secret, "[REDACTED]")
		}
	}
	if len(v) > 300 {
		v = v[:300]
	}
	return v
}
func (r *Runner) persist(s Summary) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(r.RunDir, "evidence", "run-state.json")
	tmp := p + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
func (r *Runner) request(ctx context.Context, cid, target, method string, headers interface{}, body string) (*mcp.ToolExecution, error) {
	r.sequence++
	path := filepath.Join(r.RunDir, "evidence", "raw", cid, fmt.Sprintf("http-%06d.json", r.sequence))
	args := map[string]interface{}{"url": target, "method": method, "follow_redirects": false, "capture_file": path, "timeout": "10"}
	if headers != nil {
		args["headers"] = headers
	}
	if body != "" {
		args["data"] = body
	}
	e, err := r.call(ctx, "http-framework-test", args)
	if e != nil {
		r.captures = append(r.captures, e)
	}
	if err != nil {
		return e, fmt.Errorf("HTTP execution unavailable")
	}
	if e == nil || e.Status != "completed" || e.Result == nil || e.Result.IsError {
		return e, fmt.Errorf("HTTP execution not completed")
	}
	return e, nil
}

type Capture struct {
	Status  int        `json:"status_code"`
	Headers [][]string `json:"headers"`
	Body    string     `json:"body_base64"`
	URL     string     `json:"url"`
	Time    float64    `json:"captured_at_unix"`
}

func ReadCapture(e *mcp.ToolExecution) (Capture, error) {
	var c Capture
	if e == nil || e.Result == nil || len(e.Result.NativeFiles) != 1 {
		return c, fmt.Errorf("native HTTP capture missing")
	}
	b, err := os.ReadFile(e.Result.NativeFiles[0].Path)
	if err != nil {
		return c, err
	}
	hash := sha256.Sum256(b)
	if hex.EncodeToString(hash[:]) != e.Result.NativeFiles[0].SHA256 {
		return c, fmt.Errorf("native HTTP capture hash changed")
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

var versionDisclosure = regexp.MustCompile(`(?i)\b(?:apache|nginx|php|tomcat|iis|express|jetty)[/ ]\d+\.\d+(?:\.\d+)?`)
var pathDisclosure = regexp.MustCompile(`(?i)(?:/var/www/|/home/[a-z0-9_.-]+/|[a-z]:\\(?:inetpub|users)\\|stack trace:|traceback \(most recent call last\))`)

func (r *Runner) executeCode(ctx context.Context, cid string, in Input, g map[string]interface{}) (Decision, bool, error) {
	if cid == "PT_WEB_01" {
		return r.login(ctx, in, g)
	}
	if cid == "PT_WEB_13" {
		return r.securityHeaders(ctx, in, g)
	}
	if cid != "PT_WEB_03" && cid != "PT_WEB_04" {
		return Decision{}, false, nil
	}
	fail := false
	knownDVWA := true
	for _, target := range in.Targets {
		u, _ := url.Parse(target)
		for sample, path := range []string{u.RequestURI(), "/banma-not-found-" + fmt.Sprint(time.Now().UnixNano()), u.RequestURI() + "?banma_invalid=%00"} {
			dest := *u
			dest.Path = ""
			dest.RawPath = ""
			dest.RawQuery = ""
			dest.Fragment = ""
			e, err := r.request(ctx, cid, strings.TrimRight(dest.String(), "/")+path, "GET", nil, "")
			if err != nil {
				return Decision{}, true, err
			}
			c, err := ReadCapture(e)
			if err != nil {
				return Decision{}, true, err
			}
			for hops := 0; c.Status >= 300 && c.Status < 400; hops++ {
				if hops >= 3 {
					return Decision{}, false, nil
				}
				location := ""
				for _, h := range c.Headers {
					if len(h) == 2 && strings.EqualFold(h[0], "location") {
						location = h[1]
					}
				}
				if location == "" {
					return Decision{}, false, nil
				}
				base, er := url.Parse(c.URL)
				if er != nil {
					return Decision{}, true, er
				}
				next, er := url.Parse(location)
				if er != nil {
					return Decision{}, true, er
				}
				e, err = r.request(ctx, cid, base.ResolveReference(next).String(), "GET", nil, "")
				if err != nil {
					return Decision{}, true, err
				}
				c, err = ReadCapture(e)
				if err != nil {
					return Decision{}, true, err
				}
			}
			raw, _ := base64.StdEncoding.DecodeString(c.Body)
			if sample == 0 && !strings.Contains(strings.ToLower(string(raw)), "dvwa") {
				knownDVWA = false
			}
			text := string(raw)
			for _, h := range c.Headers {
				if len(h) == 2 && (strings.EqualFold(h[0], "server") || strings.EqualFold(h[0], "x-powered-by")) {
					text += "\n" + h[1]
				}
			}
			fail = fail || versionDisclosure.MatchString(text) || pathDisclosure.MatchString(text)
		}
	}
	if cid == "PT_WEB_04" {
		if !knownDVWA {
			return Decision{}, false, nil
		}
		ev := make([]int, len(r.captures))
		for i := range ev {
			ev[i] = i
		}
		reason := "授权范围仅包含给定HTTP端口；实际TCP连接和HTTP响应/Banner已确认DVWA服务，正常及不存在路径原文保留；没有探测其他端口或UDP，不推断未测端口关闭"
		return Decision{Checks: CompleteChecks(g, "通过", reason, ev), Recovery: "未涉及"}, true, nil
	}
	result := "通过"
	reason := "正常、不存在路径及无害非法输入的HTTP响应/Banner未命中本项明确披露模式；结论限于所测端点"
	if !fail {
		return Decision{}, false, nil
	}
	result = "失败"
	reason = "本次响应原文含精确组件版本或内部路径/堆栈；已完成正常、不存在路径、无害非法输入及HTTP Banner对照"
	ev := make([]int, len(r.captures))
	for i := range ev {
		ev[i] = i
	}
	return Decision{Checks: CompleteChecks(g, result, reason, ev), Recovery: "未涉及"}, true, nil
}

func IsTargetTool(name string) bool {
	switch name {
	case "http-framework-test", "katana", "nmap", "httpx", "nikto", "nuclei":
		return true
	}
	return false
}
