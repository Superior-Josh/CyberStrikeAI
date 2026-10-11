package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/mcp"
)

// The controller uses the same registered tool and provenance path, with a Go
// HTTP implementation so Python startup cannot stretch every login sample.
// Eino and ordinary tool calls continue using the existing CLI implementation.
func (e *Executor) executeBanmaHTTP(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
	if blocked := e.checkBanmaCall(ctx, "http-framework-test", args); blocked != nil {
		return blocked, nil
	}
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}
	target, _ := args["url"].(string)
	body, _ := args["data"].(string)
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP request")
	}
	if raw, ok := args["headers"]; ok {
		b, _ := json.Marshal(raw)
		var h map[string]string
		if json.Unmarshal(b, &h) != nil {
			return nil, fmt.Errorf("headers must be an object")
		}
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("User-Agent", "CyberStrikeAI-Banma/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, fmt.Errorf("request capture failed")
	}
	wire, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(dump)))
	if err != nil {
		return nil, err
	}
	requestHeaders := [][]string{{"Host", wire.Host}}
	for k, vs := range wire.Header {
		for _, v := range vs {
			requestHeaders = append(requestHeaders, []string{k, v})
		}
	}
	timeout := 10 * time.Second
	if raw, ok := args["timeout"].(string); ok {
		if n, er := strconv.ParseFloat(raw, 64); er == nil && n > 0 {
			timeout = time.Duration(n * float64(time.Second))
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	path, _ := args["capture_file"].(string)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("unique capture file unavailable")
	}
	peer := ""
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { peer = info.Conn.RemoteAddr().String() }}))
	requestStarted := time.Now()
	response, callErr := client.Do(req)
	capture := map[string]interface{}{"source": "http-framework-test native response capture", "tcp_peer": peer, "captured_at_unix": float64(time.Now().UnixNano()) / 1e9, "method": method, "url": target, "input_url": target, "wire_request_target": req.URL.RequestURI(), "request_headers": requestHeaders, "request_body_base64": base64.StdEncoding.EncodeToString([]byte(body)), "headers": [][]string{}, "body_base64": "", "body_length": 0}
	if response != nil {
		defer response.Body.Close()
		raw, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			callErr = readErr
		}
		headers := [][]string{}
		for k, vs := range response.Header {
			for _, v := range vs {
				headers = append(headers, []string{k, v})
			}
		}
		capture["status_code"] = response.StatusCode
		capture["http_version"] = response.Proto
		capture["headers"] = headers
		capture["body_base64"] = base64.StdEncoding.EncodeToString(raw)
		capture["body_length"] = len(raw)
	}
	capture["request_started_at_unix"] = float64(requestStarted.UnixNano()) / 1e9
	capture["request_ended_at_unix"] = float64(time.Now().UnixNano()) / 1e9
	capture["elapsed_seconds"] = time.Since(requestStarted).Seconds()
	if callErr != nil {
		capture["error"] = callErr.Error()
	}
	raw, err := json.Marshal(capture)
	if err == nil {
		_, err = f.Write(raw)
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return nil, fmt.Errorf("capture write failed")
	}
	result := &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: fmt.Sprintf("HTTP capture saved; status=%v; raw response in native capture_file", capture["status_code"])}}}
	if callErr != nil {
		result.IsError = true
		result.Content[0].Text = "HTTP operation failed; actual error is in the native capture"
	}
	e.attachNativeFiles("http-framework-test", args, result)
	return result, nil
}
