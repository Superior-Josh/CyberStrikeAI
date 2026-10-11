package handler

import (
	"cyberstrike-ai/internal/banma"
	"testing"
)

func TestBanmaEntryExtractsExplicitInputAndDoesNotResumeOrdinaryFollowup(t *testing.T) {
	input, err := banmaInput(&ChatRequest{Role: "斑马安全渗透测试", Message: "测试127.0.0.1:4280，账号 user1 密码 fixture-secret，只读，不要修改安全等级"})
	if err != nil || input == nil || len(input.Targets) != 1 || input.Targets[0] != "http://127.0.0.1:4280" || input.Username != "user1" || input.Password != "fixture-secret" || input.WriteAuthorized {
		t.Fatalf("input was guessed or lost: %v", err)
	}
	if p, err := banmaInput(&ChatRequest{Role: "斑马安全渗透测试", Message: "总结刚才结果"}); err != nil || p != nil {
		t.Fatal("followup resumed target work")
	}
	if p, err := banmaInput(&ChatRequest{Role: "other", Message: "http://127.0.0.1:4280", Banma: &banma.Input{Targets: []string{"http://127.0.0.1:4280"}}}); err != nil || p != nil {
		t.Fatal("other role changed")
	}
}
