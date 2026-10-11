package multiagent

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/compose"
)

func TestRuntimeBoundaryDenialIsSoftAndNeverRunsTool(t *testing.T) {
	ctx := WithHITLToolInterceptor(context.Background(), func(context.Context, string, string) (string, error) {
		return "", NewRuntimeBoundaryError(`{"blocked":true,"reason":"fixture"}`)
	})
	invoked := false
	invokable := hitlInvokableToolCallMiddleware()(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		invoked = true
		return nil, nil
	})
	out, err := invokable(ctx, &compose.ToolInput{Name: "read_file", Arguments: `{}`})
	if err != nil || invoked || !strings.Contains(out.Result, "blocked") {
		t.Fatal("boundary denial aborted run or invoked tool")
	}
	streamable := hitlStreamableToolCallMiddleware()(func(context.Context, *compose.ToolInput) (*compose.StreamToolOutput, error) {
		invoked = true
		return nil, nil
	})
	stream, err := streamable(ctx, &compose.ToolInput{Name: "execute", Arguments: `{}`})
	if err != nil || invoked {
		t.Fatal("stream boundary denial aborted or invoked tool")
	}
	text, err := hitlCollectStringStream(stream.Result)
	if err != nil || !strings.Contains(text, "blocked") {
		t.Fatal("stream denial result lost")
	}
}
