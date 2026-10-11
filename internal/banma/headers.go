package banma

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// sample follows only explicitly checked redirects through the existing call
// boundary. Every hop has its own native request/response and execution ID.
func (r *Runner) sample(ctx context.Context, cid, target string) (Capture, error) {
	for hops := 0; hops < 4; hops++ {
		e, err := r.request(ctx, cid, target, "GET", nil, "")
		if err != nil {
			return Capture{}, err
		}
		c, err := ReadCapture(e)
		if err != nil {
			return c, err
		}
		if c.Status < 300 || c.Status >= 400 {
			return c, nil
		}
		loc := ""
		for _, h := range c.Headers {
			if len(h) == 2 && strings.EqualFold(h[0], "location") {
				loc = h[1]
			}
		}
		base, err := url.Parse(target)
		if err != nil || loc == "" {
			return c, fmt.Errorf("redirect requires discovery")
		}
		next, err := url.Parse(loc)
		if err != nil {
			return c, err
		}
		target = base.ResolveReference(next).String()
	}
	return Capture{}, fmt.Errorf("redirect loop")
}
func (r *Runner) securityHeaders(ctx context.Context, in Input, g map[string]interface{}) (Decision, bool, error) {
	missing := []string{}
	htmlSeen := 0
	for _, target := range in.Targets {
		u, _ := url.Parse(target)
		if u == nil {
			return Decision{}, false, nil
		}
		root := *u
		root.Path = ""
		root.RawQuery = ""
		root.Fragment = ""
		for _, path := range []string{"/login.php", "/about.php", "/banma-not-found-" + fmt.Sprint(time.Now().UnixNano())} {
			c, err := r.sample(ctx, "PT_WEB_13", strings.TrimRight(root.String(), "/")+path)
			if err != nil {
				return Decision{}, true, err
			}
			headers := map[string][]string{}
			for _, p := range c.Headers {
				if len(p) == 2 {
					headers[strings.ToLower(p[0])] = append(headers[strings.ToLower(p[0])], p[1])
				}
			}
			for _, key := range []string{"content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"} {
				if len(headers[key]) > 1 {
					return Decision{}, false, nil
				}
			}
			body, _ := base64.StdEncoding.DecodeString(c.Body)
			text := strings.ToLower(string(body))
			if !strings.Contains(strings.Join(headers["content-type"], ";"), "text/html") {
				return Decision{}, false, nil
			}
			htmlSeen++
			// Only claim a missing control; complex or equivalent policies go to Eino.
			if len(headers["content-security-policy"]) == 0 && !strings.Contains(text, "content-security-policy") {
				missing = append(missing, "HTML缺生效CSP且无meta等效策略")
			}
			if len(headers["x-frame-options"]) == 0 && !strings.Contains(strings.Join(headers["content-security-policy"], ";"), "frame-ancestors") {
				missing = append(missing, "缺嵌入限制")
			}
			if !strings.EqualFold(strings.Join(headers["x-content-type-options"], ""), "nosniff") {
				missing = append(missing, "缺nosniff")
			}
			if u.Scheme == "https" && len(headers["strict-transport-security"]) == 0 {
				missing = append(missing, "敏感HTTPS入口缺HSTS")
			}
		}
	}
	if htmlSeen == 0 || len(missing) == 0 {
		return Decision{}, false, nil
	}
	ev := make([]int, len(r.captures))
	for i := range ev {
		ev[i] = i
	}
	reason := "已按登录/正常说明页/不存在路径HTML用途核对本轮原生响应头及页面，强制控制缺失：" + strings.Join(missing, "、") + "；不以头存在推断复杂策略有效"
	return Decision{Checks: CompleteChecks(g, "失败", reason, ev), Recovery: "未涉及"}, true, nil
}
