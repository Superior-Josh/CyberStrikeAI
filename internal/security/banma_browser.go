package security

import (
	"context"
	"cyberstrike-ai/internal/mcp"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Browser originals are CDP messages and the actual runtime snapshot. They are
// not represented as HTTP wire bytes or as a simulated DOM.
type browserCDP struct {
	conn      *websocket.Conn
	mu        sync.Mutex
	writeMu   sync.Mutex
	next      int
	pending   map[int]chan map[string]interface{}
	events    chan map[string]interface{}
	originals []map[string]interface{}
	cancel    context.CancelFunc
	ctx       context.Context
	done      chan struct{}
	bytes     int
}

func (c *browserCDP) command(ctx context.Context, method string, params interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	c.next++
	id := c.next
	reply := make(chan map[string]interface{}, 1)
	c.pending[id] = reply
	c.mu.Unlock()
	c.writeMu.Lock()
	err := c.conn.WriteJSON(map[string]interface{}{"id": id, "method": method, "params": params})
	c.writeMu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case result := <-reply:
		if result["error"] != nil {
			return nil, fmt.Errorf("browser protocol rejected %s", method)
		}
		body, _ := result["result"].(map[string]interface{})
		return body, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *browserCDP) read() {
	defer close(c.done)
	for {
		var value map[string]interface{}
		if c.conn.ReadJSON(&value) != nil {
			c.cancel()
			return
		}
		c.mu.Lock()
		encoded, _ := json.Marshal(value)
		c.bytes += len(encoded)
		if c.bytes > 16<<20 {
			c.mu.Unlock()
			c.cancel()
			return
		}
		c.originals = append(c.originals, value)
		if n, ok := value["id"].(float64); ok {
			if ch := c.pending[int(n)]; ch != nil {
				ch <- value
				delete(c.pending, int(n))
			}
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		method, _ := value["method"].(string)
		if method == "Fetch.requestPaused" || method == "Page.loadEventFired" || method == "Page.javascriptDialogOpening" || method == "Network.loadingFinished" {
			select {
			case c.events <- value:
			case <-c.ctx.Done():
				return
			}
		}
	}
}
func browserBinary() string {
	for _, p := range []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "chromium-browser"} {
		if resolved, err := exec.LookPath(p); err == nil {
			return resolved
		}
	}
	return ""
}
func (e *Executor) executeBanmaBrowser(parent context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
	if !mcp.HasBanmaCallCheck(parent) {
		return banmaFailure("AUTHORIZATION_BOUNDARY", "browser_probe", "浏览器观察仅供冻结授权的斑马单项使用"), nil
	}
	if blocked := e.checkBanmaCall(parent, "http-framework-test", args); blocked != nil {
		return blocked, nil
	}
	method, _ := args["method"].(string)
	if method != "" && !strings.EqualFold(method, "GET") {
		return banmaFailure("INVALID_INPUT", "method", "浏览器观察只导航GET，不自动提交业务表单"), nil
	}
	target, _ := args["url"].(string)
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("browser URL invalid")
	}
	for key := range u.Query() {
		if strings.Contains(strings.ToLower(key), "password") {
			return banmaFailure("AUTHORIZATION_BOUNDARY", "url", "浏览器观察不额外提交口令或修改口令"), nil
		}
	}
	path, _ := args["capture_file"].(string)
	trace := map[string]interface{}{"source": "browser-runtime native CDP export", "url": target, "representation": "actual browser protocol messages and runtime values; not HTTP wire bytes"}
	result := &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "Browser runtime original saved; inspect the derived view with its original hash"}}}
	save := func(reason error) (*mcp.ToolResult, error) {
		if reason != nil {
			trace["error"] = reason.Error()
			result.IsError = true
			result.Content[0].Text = "Browser observation incomplete; actual driver error is preserved in the original"
		}
		trace["captured_at_unix"] = float64(time.Now().UnixNano()) / 1e9
		data, err := json.Marshal(trace)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, fmt.Errorf("browser original write failed")
		}
		e.attachNativeFiles("http-framework-test", args, result)
		return result, nil
	}
	binary := browserBinary()
	if binary == "" {
		return save(fmt.Errorf("existing Chrome executable unavailable; no dependency installed"))
	}
	profile, err := os.MkdirTemp("", "banma-browser-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(profile)
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--password-store=basic", "--use-mock-keychain", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	_ = prepareShellCmdSession(cmd)
	if err = cmd.Start(); err != nil {
		return save(err)
	}
	defer func() { terminateProcessGroup(cmd.Process.Pid, cmd); _ = cmd.Wait() }()
	var port string
	for port == "" {
		data, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		if err == nil {
			port = strings.Split(string(data), "\n")[0]
		}
		if port != "" {
			break
		}
		select {
		case <-ctx.Done():
			return save(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	if _, err = strconv.Atoi(port); err != nil {
		return save(fmt.Errorf("invalid browser control port"))
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+port+"/json/list", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return save(err)
	}
	var pages []map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&pages)
	response.Body.Close()
	if err != nil || len(pages) == 0 {
		return save(fmt.Errorf("browser page unavailable"))
	}
	endpoint, _ := pages[0]["webSocketDebuggerUrl"].(string)
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		return save(err)
	}
	defer conn.Close()
	c := &browserCDP{conn: conn, pending: map[int]chan map[string]interface{}{}, events: make(chan map[string]interface{}, 64), cancel: cancel, ctx: ctx, done: make(chan struct{})}
	conn.SetReadLimit(16 << 20)
	go c.read()
	loadedSignal := make(chan struct{}, 1)
	var blockedMu sync.Mutex
	blockedRequest := false
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		count := 0
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-c.events:
				name, _ := event["method"].(string)
				params, _ := event["params"].(map[string]interface{})
				switch name {
				case "Page.loadEventFired":
					select {
					case loadedSignal <- struct{}{}:
					default:
					}
				case "Page.javascriptDialogOpening":
					_, _ = c.command(ctx, "Page.handleJavaScriptDialog", map[string]interface{}{"accept": false})
				case "Network.loadingFinished":
					_, _ = c.command(ctx, "Network.getResponseBody", map[string]interface{}{"requestId": params["requestId"]})
				case "Fetch.requestPaused":
					id, _ := params["requestId"].(string)
					request, _ := params["request"].(map[string]interface{})
					rawURL, _ := request["url"].(string)
					verb, _ := request["method"].(string)
					parsed, _ := url.Parse(rawURL)
					count++
					deny := parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || count > 20 || (verb != "GET" && verb != "HEAD")
					actualCookies, cookieErr := c.command(ctx, "Network.getCookies", map[string]interface{}{"urls": []string{rawURL}})
					if cookieErr != nil {
						return
					}
					cookieValues := []string{}
					if cookies, ok := actualCookies["cookies"].([]interface{}); ok {
						for _, value := range cookies {
							if cookie, ok := value.(map[string]interface{}); ok {
								cookieValues = append(cookieValues, fmt.Sprint(cookie["name"])+"="+fmt.Sprint(cookie["value"]))
							}
						}
					}
					callArgs := map[string]interface{}{"url": rawURL, "method": verb, "headers": request["headers"], "cookies": strings.Join(cookieValues, "; "), "data": request["postData"]}
					if mcp.CheckBanmaOperation(ctx, "http-framework-test", callArgs) != nil {
						deny = true
					}
					if parsed != nil {
						if parsed.Host != u.Host {
							deny = true
						}
						for key := range parsed.Query() {
							lower := strings.ToLower(key)
							if strings.Contains(lower, "password") || lower == "clear" || lower == "create_db" || lower == "delete" || lower == "change" {
								deny = true
							}
						}
					}
					if deny {
						blockedMu.Lock()
						blockedRequest = true
						blockedMu.Unlock()
						_, _ = c.command(ctx, "Fetch.failRequest", map[string]interface{}{"requestId": id, "errorReason": "BlockedByClient"})
					} else {
						_, _ = c.command(ctx, "Fetch.continueRequest", map[string]interface{}{"requestId": id})
					}
				}
			}
		}
	}()
	finish := func(reason error) (*mcp.ToolResult, error) {
		cancel()
		conn.Close()
		<-workerDone
		<-c.done
		blockedMu.Lock()
		trace["controller_blocked_request"] = blockedRequest
		blockedMu.Unlock()
		c.mu.Lock()
		trace["protocol_messages"] = append([]map[string]interface{}{}, c.originals...)
		c.mu.Unlock()
		return save(reason)
	}
	for _, name := range []string{"Page.enable", "Network.enable", "Runtime.enable"} {
		if _, err = c.command(ctx, name, map[string]interface{}{}); err != nil {
			return finish(err)
		}
	}
	if cookies, ok := args["browser_cookies"].([]interface{}); ok && len(cookies) > 0 {
		if _, err = c.command(ctx, "Network.setCookies", map[string]interface{}{"cookies": cookies}); err != nil {
			return finish(err)
		}
	}
	if _, err = c.command(ctx, "Fetch.enable", map[string]interface{}{"patterns": []map[string]string{{"urlPattern": "*"}}}); err != nil {
		return finish(err)
	}
	if _, err = c.command(ctx, "Network.setBlockedURLs", map[string]interface{}{"urls": []string{"ws://*", "wss://*", "file://*", "ftp://*"}}); err != nil {
		return finish(err)
	}
	navigation, err := c.command(ctx, "Page.navigate", map[string]interface{}{"url": target})
	if err != nil {
		return finish(err)
	}
	if message, ok := navigation["errorText"].(string); ok && message != "" {
		return finish(fmt.Errorf("browser navigation failed: %s", message))
	}
	select {
	case <-loadedSignal:
	case <-ctx.Done():
		return finish(ctx.Err())
	}
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return finish(ctx.Err())
	}

	snapshot, err := c.command(ctx, "Runtime.evaluate", map[string]interface{}{"expression": `JSON.stringify({url:location.href,ready_state:document.readyState,engine_control:1+1,dom:document.documentElement.outerHTML,local_storage:Object.fromEntries(Object.entries(localStorage)),session_storage:Object.fromEntries(Object.entries(sessionStorage))})`, "returnByValue": true})
	if err != nil {
		return finish(err)
	}
	remote, _ := snapshot["result"].(map[string]interface{})
	text, _ := remote["value"].(string)
	var state map[string]interface{}
	if json.Unmarshal([]byte(text), &state) != nil {
		return finish(fmt.Errorf("browser runtime snapshot unavailable"))
	}
	trace["runtime"] = state
	runtimeURL, _ := url.Parse(fmt.Sprint(state["url"]))
	if runtimeURL == nil || runtimeURL.Host != u.Host || state["ready_state"] != "complete" {
		return finish(fmt.Errorf("browser did not reach a complete authorized page"))
	}
	cookieState, cookieErr := c.command(ctx, "Network.getCookies", map[string]interface{}{"urls": []string{fmt.Sprint(state["url"])}})
	if cookieErr == nil {
		trace["cookies"] = cookieState["cookies"]
	}
	blockedMu.Lock()
	blocked := blockedRequest
	blockedMu.Unlock()
	if blocked {
		return finish(fmt.Errorf("browser request crossed observation scope or budget; native requests preserved"))
	}
	return finish(nil)
}
