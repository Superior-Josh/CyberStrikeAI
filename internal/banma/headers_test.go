package banma

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func TestHeaderEvaluatorDoesNotGuessComplexOrRepeatedPolicy(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		r := &Runner{RunDir: t.TempDir()}
		n := 0
		r.Call = func(ctx context.Context, name string, args map[string]interface{}) (*mcp.ToolExecution, error) {
			n++
			headers := [][]string{{"Content-Type", "text/html"}}
			if duplicate {
				headers = append(headers, []string{"X-Content-Type-Options", "nosniff"}, []string{"X-Content-Type-Options", "nosniff"})
			}
			raw, _ := json.Marshal(Capture{Status: 200, URL: args["url"].(string), Headers: headers, Body: base64.StdEncoding.EncodeToString([]byte("<html><title>DVWA</title></html>"))})
			path := filepath.Join(r.RunDir, fmt.Sprintf("%d.json", n))
			os.WriteFile(path, raw, 0600)
			e := fixtureExecution(name, map[string]string{"output": "fixture"})
			e.Result.NativeFiles = []mcp.NativeFileRef{{Path: path}}
			return e, nil
		}
		d, supported, err := r.securityHeaders(context.Background(), Input{Targets: []string{"http://127.0.0.1:4280"}}, map[string]interface{}{"case": map[string]interface{}{"steps": []interface{}{"header control"}}})
		if err != nil {
			t.Fatal(err)
		}
		if duplicate && supported {
			t.Fatal("repeated policy was declared invalid by joining strings")
		}
		if !duplicate && (!supported || d.Checks[0].Result != "失败" || n != 3) {
			t.Fatal("plain missing controls not collected/judged")
		}
	}
}
