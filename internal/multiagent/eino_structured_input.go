package multiagent

import "context"

type structuredEinoInputKey struct{}

// Structured consumers supply decoded native material directly. Prose preview
// artifacts and manual file extraction must not replace that machine contract.
func WithStructuredEinoInput(ctx context.Context) context.Context {
	return context.WithValue(ctx, structuredEinoInputKey{}, true)
}
func einoStructuredInput(ctx context.Context) bool {
	v, _ := ctx.Value(structuredEinoInputKey{}).(bool)
	return v
}
