package handler

import (
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestBanmaRoleSystemContractIsOptInAndEnabled(t *testing.T) {
	roles := map[string]config.RoleConfig{
		"斑马安全渗透测试": {Enabled: true, UserPrompt: "  fixed-case contract  "},
		"其他角色":     {Enabled: true, UserPrompt: "other contract"},
	}
	if got := banmaRoleSystemBlock("斑马安全渗透测试", roles); got != "fixed-case contract" {
		t.Fatalf("role system block = %q", got)
	}
	if got := banmaRoleSystemBlock("其他角色", roles); got != "" {
		t.Fatalf("changed unrelated role: %q", got)
	}
	roles["斑马安全渗透测试"] = config.RoleConfig{Enabled: false, UserPrompt: "disabled"}
	if got := banmaRoleSystemBlock("斑马安全渗透测试", roles); got != "" {
		t.Fatalf("disabled role injected: %q", got)
	}
}
