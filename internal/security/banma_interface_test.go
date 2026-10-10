package security

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

// This fixture checks the real MCP -> executor -> argv -> native file path.
// It does not test a target or implement either planned banma tool.
func TestBanmaObjectPayloadAndNativeEvidenceThroughMCP(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python is required for this interface fixture")
	}
	outputPath := filepath.Join(t.TempDir(), "native evidence.txt")
	payload := map[string]interface{}{
		"path": outputPath,
		"text": "OFFLINE FIXTURE ONLY\n中文；引号\" 和路径空格\n",
		"nested": map[string]interface{}{
			"items":   []interface{}{"正常对照", "变体"},
			"enabled": true,
		},
	}
	logger := zap.NewNop()
	server := mcp.NewServer(logger)
	cfg := &config.SecurityConfig{Tools: []config.ToolConfig{{
		Name: "banma-interface-fixture", Command: python, Enabled: true,
		Args:       []string{"-c", "import json,sys,pathlib; assert sys.argv[1]=='--payload'; assert len(sys.argv)==3; p=json.loads(sys.argv[2]); pathlib.Path(p['path']).write_text(p['text'],encoding='utf-8'); print(json.dumps(p,ensure_ascii=False))"},
		Parameters: []config.ParameterConfig{{Name: "payload", Type: "object", Required: true, Flag: "--payload", Format: "flag"}},
	}}}
	executor := NewExecutor(cfg, server, logger)
	executor.RegisterTools(server)
	result, executionID, err := server.CallTool(context.Background(), "banma-interface-fixture", map[string]interface{}{"payload": payload})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("MCP fixture failed: %v, %#v", err, result)
	}
	if executionID == "" {
		t.Fatal("MCP did not return a source execution ID")
	}
	var returned map[string]interface{}
	if err := json.Unmarshal([]byte(mcp.ToolResultPlainText(result)), &returned); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(returned, payload) {
		t.Fatalf("object payload changed across argv: %#v", returned)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil || string(data) != payload["text"] {
		t.Fatalf("native evidence file mismatch: %v", err)
	}
	record, exists := server.GetExecution(executionID)
	if !exists || record.Status != "completed" {
		t.Fatalf("execution not completed: %#v", record)
	}
}
