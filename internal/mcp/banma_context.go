package mcp

import "context"

type banmaControllerKey struct{}
type banmaCallCheckKey struct{}

// The fixed-case controller owns saving; this cannot be supplied by model JSON.
func WithBanmaController(ctx context.Context) context.Context {
	return context.WithValue(ctx, banmaControllerKey{}, true)
}
func IsBanmaController(ctx context.Context) bool {
	v, _ := ctx.Value(banmaControllerKey{}).(bool)
	return v
}
func WithBanmaCallCheck(ctx context.Context, check func(string, map[string]interface{}) *ToolResult) context.Context {
	return context.WithValue(ctx, banmaCallCheckKey{}, check)
}
func CheckBanmaOperation(ctx context.Context, name string, args map[string]interface{}) *ToolResult {
	if f, ok := ctx.Value(banmaCallCheckKey{}).(func(string, map[string]interface{}) *ToolResult); ok {
		return f(name, args)
	}
	return nil
}
func WithoutBanmaController(ctx context.Context) context.Context {
	return context.WithValue(ctx, banmaControllerKey{}, false)
}

type banmaArgumentsKey struct{}

func WithBanmaArguments(ctx context.Context, prepare func(string, map[string]interface{}) map[string]interface{}) context.Context {
	return context.WithValue(ctx, banmaArgumentsKey{}, prepare)
}
func PrepareBanmaArguments(ctx context.Context, name string, args map[string]interface{}) map[string]interface{} {
	if f, ok := ctx.Value(banmaArgumentsKey{}).(func(string, map[string]interface{}) map[string]interface{}); ok {
		return f(name, args)
	}
	return args
}

type banmaJudgmentKey struct{}

func WithBanmaJudgment(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, banmaJudgmentKey{}, method)
}
func BanmaJudgmentMethod(ctx context.Context) string {
	v, _ := ctx.Value(banmaJudgmentKey{}).(string)
	if v == "code" || v == "eino" {
		return v
	}
	return "code_or_eino"
}

func HasBanmaCallCheck(ctx context.Context) bool {
	_, ok := ctx.Value(banmaCallCheckKey{}).(func(string, map[string]interface{}) *ToolResult)
	return ok
}
