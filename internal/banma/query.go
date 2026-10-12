package banma

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"net/url"
	"strings"
)

// Query execution uses observed menus and forms, not guessed target paths.
// Each variant gets its own fresh form response in the authenticated client.
func (r *Runner) prepareQueryChecks(ctx context.Context, g map[string]interface{}) (Decision, bool, error) {
	c, _ := g["case"].(map[string]interface{})
	raw, ok := c["query_budget"]
	if !ok || r.session == nil {
		return Decision{}, false, nil
	}
	var budget struct {
		Rounds  int    `json:"rounds"`
		Max     int    `json:"max_requests"`
		Timeout int    `json:"timeout_seconds"`
		Normal  string `json:"normal_value"`
		True    string `json:"true_value"`
		False   string `json:"false_value"`
	}
	data, _ := json.Marshal(raw)
	if err := json.Unmarshal(data, &budget); err != nil {
		return Decision{}, true, err
	}
	if budget.Rounds < 1 || budget.Max < 1 || budget.Timeout < 1 || budget.Normal == "" || budget.True == "" || budget.False == "" {
		return Decision{}, true, fmt.Errorf("invalid query_budget")
	}
	headers, _ := r.session["headers"].(map[string]string)
	h := map[string]string{}
	for key, value := range headers {
		h[key] = value
	}
	base, _ := url.Parse(toString(r.session["authenticated_url"]))
	if base == nil {
		return Decision{}, false, nil
	}
	var menu string
	for i := len(r.captures) - 1; i >= 0; i-- {
		capture, err := ReadCapture(r.captures[i])
		if err == nil && capture.URL == base.String() {
			body, _ := base64.StdEncoding.DecodeString(capture.Body)
			menu = string(body)
			break
		}
	}
	doc, err := html.Parse(strings.NewReader(menu))
	if err != nil {
		return Decision{}, false, nil
	}
	endpoints := []string{}
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					rel, err := url.Parse(a.Val)
					if err == nil {
						u := base.ResolveReference(rel)
						if (strings.HasSuffix(u.Path, "/sqli/") || strings.HasSuffix(u.Path, "/sqli_blind/")) && !seen[u.String()] {
							seen[u.String()] = true
							endpoints = append(endpoints, u.String())
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if len(endpoints) != 2 {
		return Decision{}, false, nil
	}
	if len(endpoints)*(budget.Rounds*3+1)*2 > budget.Max {
		return Decision{}, true, fmt.Errorf("query request budget insufficient for paired controls")
	}
	for _, endpoint := range endpoints {
		values := []string{}
		for n := 0; n < budget.Rounds; n++ {
			values = append(values, budget.Normal, budget.True, budget.False)
		}
		values = append(values, budget.Normal)
		for _, value := range values {
			record, err := r.request(ctx, "PT_WEB_AUTH_08", endpoint, "GET", h, "", budget.Timeout)
			if err != nil {
				return Decision{}, true, err
			}
			capture, err := ReadCapture(record)
			if err != nil {
				return Decision{}, true, err
			}
			if capture.Status != 200 {
				return Decision{}, true, fmt.Errorf("query form unavailable; no variant submitted")
			}
			body, _ := base64.StdEncoding.DecodeString(capture.Body)
			fields, err := observedQueryForm(string(body), endpoint)
			if err != nil {
				return Decision{}, false, nil
			}
			jar := map[string]string{}
			for _, part := range strings.Split(h["Cookie"], ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 {
					jar[kv[0]] = kv[1]
				}
			}
			cookies(capture, jar)
			h["Cookie"] = cookieHeader(jar)
			fields.Set("id", value)
			target, _ := url.Parse(endpoint)
			target.RawQuery = fields.Encode()
			record, err = r.request(ctx, "PT_WEB_AUTH_08", target.String(), "GET", h, "", budget.Timeout)
			if err != nil {
				return Decision{}, true, err
			}
			capture, err = ReadCapture(record)
			if err != nil {
				return Decision{}, true, err
			}
			response, _ := base64.StdEncoding.DecodeString(capture.Body)
			if capture.Status != 200 || strings.Contains(strings.ToLower(string(response)), "csrf token is incorrect") || !observedIdentity(string(response), toString(r.session["username"])) {
				return Decision{}, true, fmt.Errorf("query authentication/CSRF control failed; no further variants")
			}
			cookies(capture, jar)
			h["Cookie"] = cookieHeader(jar)
		}
	}
	r.preparedOnly = true
	return Decision{}, false, nil // Eino analyzes the complete existing originals only.
}

func observedQueryForm(body, endpoint string) (url.Values, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse(endpoint)
	var found url.Values
	attrs := func(n *html.Node) map[string]string {
		m := map[string]string{}
		for _, a := range n.Attr {
			m[a.Key] = a.Val
		}
		return m
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			a := attrs(n)
			rel, er := url.Parse(a["action"])
			if er == nil {
				destination := base.ResolveReference(rel)
				if destination.Host == base.Host && destination.Path == base.Path && (a["method"] == "" || strings.EqualFold(a["method"], "get")) {
					fields := url.Values{}
					var inputs func(*html.Node)
					inputs = func(x *html.Node) {
						if x.Type == html.ElementNode && (x.Data == "input" || x.Data == "select") {
							v := attrs(x)
							if v["name"] != "" && v["disabled"] == "" {
								fields.Set(v["name"], v["value"])
							}
						}
						for child := x.FirstChild; child != nil; child = child.NextSibling {
							inputs(child)
						}
					}
					inputs(n)
					if fields.Has("id") && fields.Has("user_token") && fields.Get("user_token") != "" {
						found = fields
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if found == nil {
		return nil, fmt.Errorf("observed query form needs Eino binding; no guessed submission")
	}
	return found, nil
}
