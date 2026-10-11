package multiagent

import (
	"cyberstrike-ai/internal/agent"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

func TestEmitToolCallsUsesUniqueFallbackIDsAcrossBatches(t *testing.T) {
	index := 0
	msg := &schema.Message{ToolCalls: []schema.ToolCall{{
		Index: &index,
		Function: schema.FunctionCall{
			Name:      "http-framework-test",
			Arguments: `{}`,
		},
	}}}
	var ids []string
	progress := func(eventType, _ string, raw interface{}) {
		if eventType != "tool_call" {
			return
		}
		data, _ := raw.(map[string]interface{})
		if id, _ := data["toolCallId"].(string); id != "" {
			ids = append(ids, id)
		}
	}
	for i := 0; i < 2; i++ {
		emitToolCallsFromMessage(msg, "agent", "agent", "conversation", "deep", progress, nil, make(map[string]int), nil)
	}
	if len(ids) != 2 {
		t.Fatalf("fallback IDs = %v, want two IDs", ids)
	}
	if ids[0] == ids[1] {
		t.Fatalf("fallback ID was reused across batches: %q", ids[0])
	}
}

func TestFixedCaseContinuationStateReachesModelMessages(t *testing.T) {
	input := []agent.ChatMessage{{Role: "system", Content: "unrelated old system"}, {Role: "system", Content: "[banma_fixed_case_completion] []\ncontinue pending cases"}, {Role: "user", Content: "fixture"}}
	messages := historyToMessages(input, nil, nil)
	if len(messages) != 2 || messages[0].Role != schema.System || !strings.Contains(messages[0].Content, "continue pending cases") {
		t.Fatalf("trusted runtime state lost: %+v", messages)
	}
}
