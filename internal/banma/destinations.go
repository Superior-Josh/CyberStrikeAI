package banma

import (
	"cyberstrike-ai/internal/mcp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
)

var payloadURL = regexp.MustCompile(`(?i)https?://[^\s"'<>?&]+`)

// Check URL-valued inputs as well as the primary target. Sending an SSRF or
// redirect payload can cause the target to access an unapproved destination.
// Origin/Referer control headers are not themselves fetch instructions.
func (r *Runner) checkPayloadDestinations(target *url.URL, data string) error {
	values := []string{data}
	var object interface{}
	if json.Unmarshal([]byte(data), &object) == nil {
		var collect func(interface{})
		collect = func(v interface{}) {
			switch x := v.(type) {
			case string:
				values = append(values, x)
			case map[string]interface{}:
				for _, item := range x {
					collect(item)
				}
			case []interface{}:
				for _, item := range x {
					collect(item)
				}
			}
		}
		collect(object)
	}
	if target != nil {
		for _, items := range target.Query() {
			values = append(values, items...)
		}
	}
	for _, value := range values {
		for i := 0; i < 4; i++ {
			next, err := url.QueryUnescape(value)
			if err != nil || next == value {
				break
			}
			value = next
		}
		value = html.UnescapeString(value)
		lower := strings.ToLower(value)
		if strings.Contains(lower, "file://") || strings.Contains(lower, "php://filter") {
			return fmt.Errorf("禁止以载荷读取靶机内部文件/源码")
		}
		for _, candidate := range payloadURL.FindAllString(value, -1) {
			destination, err := url.Parse(candidate)
			allowed := false
			for _, raw := range r.input.Targets {
				authorized, _ := url.Parse(raw)
				if err == nil && destination != nil && authorized != nil && destination.User == nil && destination.Host == authorized.Host {
					allowed = true
				}
			}
			if !allowed {
				return fmt.Errorf("载荷目的地不在冻结授权主机和端口内")
			}
		}
	}
	return nil
}

// A read-only revision cannot validate a pass using historically unauthorized
// probes. Keep the original records and mark the result pending instead.
func (r *Runner) reviewScope(guide map[string]interface{}) error {
	if len(r.captures) == 0 {
		return nil
	}
	raw, err := json.Marshal(guide["execution_scope"])
	if err != nil {
		return err
	}
	var frozen Input
	if err = json.Unmarshal(raw, &frozen); err != nil || len(frozen.Targets) == 0 {
		return fmt.Errorf("missing frozen review authorization")
	}
	r.input.Targets = frozen.Targets
	for _, record := range r.captures {
		if record == nil || record.ToolName != "http-framework-test" || record.Result == nil || len(record.Result.NativeFiles) == 0 {
			continue
		}
		for _, ref := range record.Result.NativeFiles {
			single := *record
			result := *record.Result
			result.NativeFiles = []mcp.NativeFileRef{ref}
			single.Result = &result
			capture, err := ReadCapture(&single)
			if err != nil {
				return err
			}
			target, err := url.Parse(capture.URL)
			if err != nil {
				return fmt.Errorf("invalid historical target")
			}
			data, err := base64.StdEncoding.DecodeString(capture.RequestBody)
			if err != nil {
				return fmt.Errorf("invalid historical request body")
			}
			if err = r.checkPayloadDestinations(target, string(data)); err != nil {
				return fmt.Errorf("原执行%s违反冻结授权：%s；不得用该轨迹验收通过", record.ID, err)
			}
		}
	}
	return nil
}
