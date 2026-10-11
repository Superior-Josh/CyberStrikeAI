package einomcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExecutionMetadataPreservesJSONAndPlainOutput(t *testing.T) {
	var decoded map[string]interface{}
	out := withExecutionMetadata(`{"ok":true,"run_dir":"fixture"}`, "actual-id", "actual-tool", "completed")
	if json.Unmarshal([]byte(out), &decoded) != nil || decoded["ok"] != true || decoded["platform_execution"].(map[string]interface{})["execution_id"] != "actual-id" {
		t.Fatal("JSON contract lost runtime execution metadata")
	}
	out = withExecutionMetadata("native scanner output", "actual-id", "nuclei", "completed")
	if !strings.HasPrefix(out, "native scanner output") || !strings.Contains(out, "actual-id") {
		t.Fatal("plain output or source ID lost")
	}
}
