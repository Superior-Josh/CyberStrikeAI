package banma

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Prepare the observed DVWA login flow in code. Other form bindings remain an
// Eino gap; no guessed registration, credential acquisition or security change.
func (r *Runner) prepareAuthenticatedSession(ctx context.Context, cid string, input Input) (map[string]interface{}, error) {
	if len(input.Targets) != 1 || input.Username == "" || input.Password == "" {
		return nil, nil
	}
	r.budget.mu.Lock()
	stopped := r.budget.NormalStopped
	r.budget.mu.Unlock()
	if stopped {
		return map[string]interface{}{"status": "unavailable", "reason": "本轮提供凭据验证已停止；不重复提交"}, nil
	}
	jar := map[string]string{}
	target := input.Targets[0]
	var capture Capture
	for hop := 0; hop < 4; hop++ {
		headers := map[string]string{}
		if value := cookieHeader(jar); value != "" {
			headers["Cookie"] = value
		}
		record, err := r.request(ctx, cid, target, "GET", headers, "")
		if err != nil {
			return nil, err
		}
		capture, err = ReadCapture(record)
		if err != nil {
			return nil, err
		}
		cookies(capture, jar)
		if capture.Status == 429 {
			r.stopNormalCredentials()
			return nil, fmt.Errorf("login discovery received 429; no credential submission")
		}
		if capture.Status < 300 || capture.Status >= 400 {
			break
		}
		next, err := captureLocation(capture, target)
		if err != nil {
			return nil, err
		}
		target = next
		if hop == 3 {
			return nil, fmt.Errorf("login discovery redirect limit reached")
		}
	}
	body, _ := base64.StdEncoding.DecodeString(capture.Body)
	if !strings.Contains(strings.ToLower(string(body)), "dvwa") {
		return nil, nil
	}
	fields, action, err := formFields(capture.Body)
	if err != nil {
		return nil, nil
	}
	destination, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if action != "" {
		relative, err := url.Parse(action)
		if err != nil {
			return nil, err
		}
		destination = destination.ResolveReference(relative)
	}
	if !strings.HasSuffix(destination.Path, "/login.php") {
		return nil, nil
	}
	fields.Set("username", input.Username)
	fields.Set("password", input.Password)
	record, err := r.request(ctx, cid, destination.String(), "POST", map[string]string{"Cookie": cookieHeader(jar), "Content-Type": "application/x-www-form-urlencoded"}, fields.Encode())
	if err != nil {
		return nil, err
	}
	capture, err = ReadCapture(record)
	if err != nil {
		return nil, err
	}
	cookies(capture, jar)
	if capture.Status == 429 {
		r.stopNormalCredentials()
		return nil, fmt.Errorf("normal login received 429; do not resubmit credentials")
	}
	for hop := 0; capture.Status >= 300 && capture.Status < 400 && hop < 4; hop++ {
		target, err = captureLocation(capture, capture.URL)
		if err != nil {
			return nil, err
		}
		record, err = r.request(ctx, cid, target, "GET", map[string]string{"Cookie": cookieHeader(jar)}, "")
		if err != nil {
			return nil, err
		}
		capture, err = ReadCapture(record)
		if err != nil {
			return nil, err
		}
		cookies(capture, jar)
	}
	body, _ = base64.StdEncoding.DecodeString(capture.Body)
	if capture.Status != 200 || !observedIdentity(string(body), input.Username) || !strings.Contains(string(body), "logout.php") {
		r.stopNormalCredentials()
		return map[string]interface{}{"status": "unavailable", "reason": "真实提交未建立已验证身份；不得另取凭据或重复未知提交"}, nil
	}
	return map[string]interface{}{"status": "identity_verified", "username": input.Username, "headers": map[string]string{"Cookie": cookieHeader(jar)}, "authenticated_url": capture.URL, "source": "this case native login and identity records; runtime-only session"}, nil
}

func (r *Runner) stopNormalCredentials() {
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	r.budget.NormalStopped = true
	r.budget.Stopped = true
}

func cookieHeader(jar map[string]string) string {
	values := []string{}
	for name, value := range jar {
		values = append(values, name+"="+value)
	}
	return strings.Join(values, "; ")
}
func captureLocation(c Capture, base string) (string, error) {
	for _, pair := range c.Headers {
		if len(pair) == 2 && strings.EqualFold(pair[0], "location") {
			u, err := url.Parse(base)
			if err != nil {
				return "", err
			}
			relative, err := url.Parse(pair[1])
			if err != nil {
				return "", err
			}
			return u.ResolveReference(relative).String(), nil
		}
	}
	return "", fmt.Errorf("redirect without observed Location")
}
