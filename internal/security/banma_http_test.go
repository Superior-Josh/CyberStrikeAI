package security

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/config"
	"go.uber.org/zap"
)

func TestControllerHTTPCapturesRealHeadersBodyAndDoesNotFollow(t *testing.T) {
	followed := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			followed++
			w.Write([]byte("unexpected"))
			return
		}
		if r.Method == "POST" && r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("content type lost")
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Location", "/next")
		w.WriteHeader(302)
	}))
	defer server.Close()
	e := NewExecutor(&config.SecurityConfig{}, nil, zap.NewNop())
	p := filepath.Join(t.TempDir(), "response.json")
	result, err := e.executeBanmaHTTP(context.Background(), map[string]interface{}{"url": server.URL, "method": "POST", "data": "field=value", "headers": map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "capture_file": p})
	if err != nil || result == nil || result.IsError || followed != 0 {
		t.Fatalf("HTTP operation/follow mismatch %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var capture map[string]interface{}
	if json.Unmarshal(raw, &capture) != nil {
		t.Fatal("not JSON")
	}
	if capture["status_code"] != float64(302) || capture["body_base64"] != "" || capture["request_body_base64"] != base64.StdEncoding.EncodeToString([]byte("field=value")) {
		t.Fatal("capture not actual request/empty response")
	}
	cookies := 0
	for _, v := range capture["headers"].([]interface{}) {
		pair := v.([]interface{})
		if pair[0] == "Set-Cookie" {
			cookies++
		}
	}
	if cookies != 2 {
		t.Fatal("multivalue headers lost")
	}
	stat, _ := os.Stat(p)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("capture secret permissions")
	}
	if _, err = e.executeBanmaHTTP(context.Background(), map[string]interface{}{"url": server.URL, "capture_file": p}); err == nil {
		t.Fatal("old native evidence overwritten")
	}
}
