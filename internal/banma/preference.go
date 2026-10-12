package banma

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DVWA's security preference can also be changed through Cookie, not only the
// settings endpoint. Bind it to the server-issued value observed in this run.
func (r *Runner) observeSecurityPreference(c Capture) {
	for _, pair := range c.Headers {
		if len(pair) != 2 || !strings.EqualFold(pair[0], "set-cookie") {
			continue
		}
		h := http.Header{}
		h.Add("Set-Cookie", pair[1])
		for _, cookie := range (&http.Response{Header: h}).Cookies() {
			if cookie.Name == "security" && cookie.Value != "" {
				r.budget.mu.Lock()
				if r.budget.SecurityCookie == "" {
					r.budget.SecurityCookie = cookie.Value
				}
				r.budget.mu.Unlock()
			}
		}
	}
}
func (r *Runner) checkSecurityPreference(args map[string]interface{}) error {
	r.budget.mu.Lock()
	expected := r.budget.SecurityCookie
	r.budget.mu.Unlock()
	if expected == "" {
		return nil
	}
	values := []string{}
	if v, ok := args["cookies"].(string); ok {
		values = append(values, v)
	}
	var collect func(interface{})
	collect = func(v interface{}) {
		switch x := v.(type) {
		case map[string]interface{}:
			for key, value := range x {
				if strings.EqualFold(key, "cookie") {
					values = append(values, fmt.Sprint(value))
				}
			}
		case []interface{}:
			for _, value := range x {
				collect(value)
			}
		case string:
			var decoded interface{}
			if json.Unmarshal([]byte(x), &decoded) == nil {
				collect(decoded)
			} else {
				for _, line := range strings.Split(x, "\n") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "cookie") {
						values = append(values, strings.TrimSpace(parts[1]))
					}
				}
			}
		}
	}
	data, _ := json.Marshal(args["headers"])
	var headers interface{}
	json.Unmarshal(data, &headers)
	collect(headers)
	for _, value := range values {
		h := http.Header{}
		h.Set("Cookie", value)
		for _, cookie := range (&http.Request{Header: h}).Cookies() {
			if cookie.Name != "security" {
				continue
			}
			actual := cookie.Value
			for i := 0; i < 4; i++ {
				decoded, err := url.QueryUnescape(actual)
				if err != nil || decoded == actual {
					break
				}
				actual = decoded
			}
			if actual != expected {
				return fmt.Errorf("请求试图改变本轮实际观察的security Cookie；禁止修改DVWA安全等级")
			}
		}
	}
	return nil
}
