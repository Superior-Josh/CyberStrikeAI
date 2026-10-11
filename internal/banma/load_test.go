package banma

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"
)

func TestControlledLoadSchedulesRealParallelRequestsWithinBudget(t *testing.T) {
	r := &Runner{RunDir: t.TempDir()}
	var count, active, peak atomic.Int64
	r.Call = func(_ context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
		count.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if args["timeout"] != "5" {
			t.Fatal("declared timeout not applied")
		}
		start := time.Now()
		time.Sleep(15 * time.Millisecond)
		capture := Capture{Status: 200, URL: args["url"].(string), Started: float64(start.UnixNano()) / 1e9, Ended: float64(time.Now().UnixNano()) / 1e9, Elapsed: time.Since(start).Seconds()}
		raw, _ := json.Marshal(capture)
		p := args["capture_file"].(string)
		os.MkdirAll(filepath.Dir(p), 0700)
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Error(err)
		}
		h := sha256.Sum256(raw)
		e := fixtureExecution(name, nil)
		e.Result.NativeFiles = []mcp.NativeFileRef{{Path: p, SHA256: hex.EncodeToString(h[:])}}
		return e, nil
	}
	g := map[string]interface{}{"case": map[string]interface{}{"id": "PT_WEB_11", "steps": []interface{}{"load", "coverage", "parallel", "stop", "recovery"}, "load_budget": map[string]interface{}{"baseline_requests": 3, "timeout_seconds": 5, "recovery_requests": 3, "recovery_window_seconds": 30, "phases": []map[string]int{{"concurrency": 2, "requests": 8}, {"concurrency": 4, "requests": 8}}}}}
	d, supported, err := r.controlledLoad(context.Background(), Input{Targets: []string{"http://offline-fixture.invalid/"}}, g)
	if err != nil || !supported || len(d.Gaps) > 0 || count.Load() != 22 || peak.Load() != 4 || len(r.captures) != 22 {
		t.Fatalf("load changed/skipped budget: count=%d peak=%d captures=%d %v", count.Load(), peak.Load(), len(r.captures), err)
	}
	paths := map[string]bool{}
	for _, e := range r.captures {
		p := e.Result.NativeFiles[0].Path
		if paths[p] {
			t.Fatal("concurrent capture collision")
		}
		paths[p] = true
	}
}
