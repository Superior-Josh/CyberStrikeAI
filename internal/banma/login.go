package banma

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// formFields reads actual HTML inputs, including the current CSRF value.
func formFields(body string) (url.Values, string, error) {
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, "", err
	}
	root, err := html.Parse(strings.NewReader(string(raw)))
	if err != nil {
		return nil, "", err
	}
	fields := url.Values{}
	action := ""
	password := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrs := map[string]string{}
			for _, a := range n.Attr {
				attrs[a.Key] = a.Val
			}
			if n.Data == "form" {
				action = attrs["action"]
			}
			if n.Data == "input" && attrs["name"] != "" {
				fields.Set(attrs["name"], attrs["value"])
				if attrs["type"] == "password" {
					password = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	if !password || fields.Get("username") == "" && !fields.Has("username") {
		return nil, "", fmt.Errorf("login form needs Eino binding")
	}
	return fields, action, nil
}
func cookies(c Capture, jar map[string]string) string {
	for _, h := range c.Headers {
		if len(h) == 2 && strings.EqualFold(h[0], "set-cookie") {
			hdr := http.Header{}
			hdr.Add("Set-Cookie", h[1])
			for _, v := range (&http.Response{Header: hdr}).Cookies() {
				jar[v.Name] = v.Value
			}
		}
	}
	parts := []string{}
	for k, v := range jar {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}
func (r *Runner) login(ctx context.Context, in Input, g map[string]interface{}) (Decision, bool, error) {
	if len(in.Targets) != 1 || in.Username == "" || in.Password == "" {
		return Decision{}, false, nil
	}
	// This concrete login binding is intentionally small; other forms go to Eino.
	target := strings.TrimRight(in.Targets[0], "/") + "/login.php"
	e, err := r.request(ctx, "PT_WEB_01", target, "GET", nil, "")
	if err != nil {
		return Decision{}, true, err
	}
	c, err := ReadCapture(e)
	if err != nil {
		return Decision{}, true, err
	}
	fields, action, err := formFields(c.Body)
	if err != nil {
		return Decision{}, false, nil
	}
	dest, _ := url.Parse(target)
	if action != "" {
		rel, er := url.Parse(action)
		if er != nil {
			return Decision{}, false, nil
		}
		dest = dest.ResolveReference(rel)
	}
	jar := map[string]string{}
	cookie := cookies(c, jar)
	fields.Set("username", in.Username)
	fields.Set("password", in.Password)
	e, err = r.request(ctx, "PT_WEB_01", dest.String(), "POST", map[string]string{"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}, fields.Encode())
	if err != nil {
		return Decision{}, true, err
	}
	c, err = ReadCapture(e)
	if err != nil {
		return Decision{}, true, err
	}
	// A redirect alone is never a successful identity control.
	location := ""
	for _, h := range c.Headers {
		if len(h) == 2 && strings.EqualFold(h[0], "location") {
			location = h[1]
		}
	}
	if location == "" {
		return Decision{}, false, nil
	}
	rel, er := url.Parse(location)
	if er != nil {
		return Decision{}, false, nil
	}
	e, err = r.request(ctx, "PT_WEB_01", dest.ResolveReference(rel).String(), "GET", map[string]string{"Cookie": cookies(c, jar)}, "")
	if err != nil {
		return Decision{}, true, err
	}
	c, err = ReadCapture(e)
	if err != nil {
		return Decision{}, true, err
	}
	b, _ := base64.StdEncoding.DecodeString(c.Body)
	if !strings.Contains(string(b), "logout.php") || !strings.Contains(strings.ToLower(string(b)), "welcome") {
		return Decision{}, false, nil
	}
	// Until its exact budget is in the YAML, never silently derive thresholds.
	cfg, _ := g["context"].(map[string]interface{})
	limits, _ := cfg["login_budget"].(map[string]interface{})
	max, ok := limits["max_attempts"].(float64)
	window, wok := limits["window_seconds"].(float64)
	if !ok || !wok || max < 1 || window <= 0 {
		return Decision{}, true, fmt.Errorf("typed login budget missing")
	}
	r.budget.mu.Lock()
	r.budget.Max = int(max)
	r.budget.Window = time.Duration(window * float64(time.Second))
	r.budget.CodeLoop = true
	r.budget.mu.Unlock()
	defer func() { r.budget.mu.Lock(); r.budget.CodeLoop = false; r.budget.mu.Unlock() }()
	started := time.Now()
	attempts := 0
	controlled := false
	for attempts < int(max) {
		if ctx.Err() != nil {
			return Decision{}, true, ctx.Err()
		}
		if time.Since(started).Seconds() >= window {
			return Decision{}, true, fmt.Errorf("login window elapsed before required samples")
		}
		// Each attempt gets valid CSRF and a separate anonymous client, same account.
		e, err = r.request(ctx, "PT_WEB_01", target, "GET", nil, "")
		if err != nil {
			return Decision{}, true, err
		}
		c, err = ReadCapture(e)
		if err != nil {
			return Decision{}, true, err
		}
		f, _, err := formFields(c.Body)
		if err != nil {
			return Decision{}, true, err
		}
		anon := map[string]string{}
		f.Set("username", in.Username)
		f.Set("password", "banma-invalid-"+fmt.Sprint(attempts+1))
		attempts++
		e, err = r.request(ctx, "PT_WEB_01", dest.String(), "POST", map[string]string{"Cookie": cookies(c, anon), "Content-Type": "application/x-www-form-urlencoded"}, f.Encode())
		if err != nil {
			return Decision{}, true, err
		}
		c, err = ReadCapture(e)
		if err != nil {
			return Decision{}, true, err
		}
		raw, _ := base64.StdEncoding.DecodeString(c.Body)
		text := strings.ToLower(string(raw))
		if c.Status == 429 || strings.Contains(text, "captcha") || strings.Contains(text, "account locked") {
			controlled = true
			break
		}
		if c.Status >= 300 && c.Status < 400 {
			loc := ""
			for _, h := range c.Headers {
				if len(h) == 2 && strings.EqualFold(h[0], "location") {
					loc = h[1]
				}
			}
			u, er := url.Parse(loc)
			if er != nil {
				return Decision{}, true, er
			}
			e, err = r.request(ctx, "PT_WEB_01", dest.ResolveReference(u).String(), "GET", map[string]string{"Cookie": cookies(c, anon)}, "")
			if err != nil {
				return Decision{}, true, err
			}
			c, err = ReadCapture(e)
			if err != nil {
				return Decision{}, true, err
			}
			raw, _ = base64.StdEncoding.DecodeString(c.Body)
			text = strings.ToLower(string(raw))
		}
		if !strings.Contains(text, "login failed") || strings.Contains(text, "csrf token is incorrect") {
			return Decision{}, true, fmt.Errorf("response did not prove a valid rejected password")
		}
	}
	if time.Since(started).Seconds() > window {
		return Decision{}, true, fmt.Errorf("actual login sample window exceeded")
	}
	// Recovery must be observed even if the requested control was absent.
	if controlled {
		r.budget.mu.Lock()
		r.budget.Stopped = true
		r.budget.mu.Unlock()
		return Decision{}, false, nil
	}
	// Fresh valid normal login and protected page establish recovery after errors.
	e, err = r.request(ctx, "PT_WEB_01", target, "GET", nil, "")
	if err != nil {
		return Decision{}, true, err
	}
	c, err = ReadCapture(e)
	if err != nil {
		return Decision{}, true, err
	}
	f, _, err := formFields(c.Body)
	if err != nil {
		return Decision{}, true, err
	}
	fresh := map[string]string{}
	f.Set("username", in.Username)
	f.Set("password", in.Password)
	e, err = r.request(ctx, "PT_WEB_01", dest.String(), "POST", map[string]string{"Cookie": cookies(c, fresh), "Content-Type": "application/x-www-form-urlencoded"}, f.Encode())
	if err != nil {
		return Decision{}, true, err
	}
	c, err = ReadCapture(e)
	if err != nil {
		return Decision{}, true, err
	}
	loc := ""
	for _, h := range c.Headers {
		if len(h) == 2 && strings.EqualFold(h[0], "location") {
			loc = h[1]
		}
	}
	u, err := url.Parse(loc)
	if err != nil || loc == "" {
		return Decision{}, false, nil
	}
	e, err = r.request(ctx, "PT_WEB_01", dest.ResolveReference(u).String(), "GET", map[string]string{"Cookie": cookies(c, fresh)}, "")
	if err != nil {
		return Decision{}, true, err
	}
	c, err = ReadCapture(e)
	if err != nil {
		return Decision{}, true, err
	}
	raw, _ := base64.StdEncoding.DecodeString(c.Body)
	if !strings.Contains(string(raw), "logout.php") {
		return Decision{}, false, nil
	}
	ev := make([]int, len(r.captures))
	for i := range ev {
		ev[i] = i
	}
	reason := fmt.Sprintf("正常身份及恢复身份均已确认；%d次同账号有效错误口令在原窗口内完成，无限速/挑战/锁定；引用逐次有效失败原文，不推断无限制", attempts)
	return Decision{Checks: CompleteChecks(g, "失败", reason, ev), Recovery: "未涉及"}, true, nil
}
