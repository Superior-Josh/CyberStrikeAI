package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
)

// Bind the check to real tool executions in this turn, not a role label or text
// mentioning a report directory. Read-only follow-up questions do not resume tests.
func (h *AgentHandler) fixedCaseCheckFor(conversationID string) func([]string) ([]agentfinalizer.FixedCaseCompletion, error) {
	return func(ids []string) ([]agentfinalizer.FixedCaseCompletion, error) {
		if h == nil || h.db == nil {
			return nil, nil
		}
		runs := map[string]bool{}
		for _, id := range ids {
			e, err := h.db.GetToolExecution(id)
			if err != nil || e == nil || e.ToolName != "banma_pentest_run_cases" || e.Status != "completed" {
				continue
			}
			mode, _ := e.Arguments["mode"].(string)
			if mode != "init" && mode != "show" && mode != "save" {
				continue
			}
			if e.ConversationID != conversationID {
				return nil, fmt.Errorf("fixed case execution conversation mismatch")
			}
			if e.Result == nil || e.Result.IsError {
				continue
			}
			var result struct {
				OK        bool   `json:"ok"`
				RunDir    string `json:"run_dir"`
				SavedPath string `json:"saved_path"`
			}
			if err := json.Unmarshal([]byte(mcp.ToolResultPlainText(e.Result)), &result); err != nil || !result.OK {
				return nil, fmt.Errorf("fixed case execution result unavailable")
			}
			dir := result.RunDir
			if mode != "init" {
				dir, _ = e.Arguments["run_dir"].(string)
			}
			if dir == "" {
				return nil, fmt.Errorf("fixed case run directory unavailable")
			}
			runs[dir] = true
		}
		if len(runs) == 0 {
			return nil, nil
		}
		var tool *config.ToolConfig
		if h.config != nil {
			for i := range h.config.Security.Tools {
				c := &h.config.Security.Tools[i]
				if c.Name == "banma_pentest_run_cases" && c.Enabled {
					tool = c
					break
				}
			}
		}
		if tool == nil {
			return nil, fmt.Errorf("fixed case tool unavailable")
		}
		dirs := make([]string, 0, len(runs))
		for dir := range runs {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		checks := make([]agentfinalizer.FixedCaseCompletion, 0, len(dirs))
		for _, dir := range dirs {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			args := append(append([]string(nil), tool.Args...), "--check-completion", "--run-dir", dir)
			output, err := exec.CommandContext(ctx, tool.Command, args...).Output()
			cancel()
			if err != nil {
				return checks, fmt.Errorf("fixed case read-only check failed")
			}
			var response struct {
				OK             bool     `json:"ok"`
				CatalogCaseIDs []string `json:"catalog_case_ids"`
				agentfinalizer.FixedCaseCompletion
			}
			if json.Unmarshal(output, &response) != nil || !response.OK || response.RunDir == "" || len(response.SelectedCaseIDs) == 0 || response.ValidSavedCount+len(response.PendingCaseIDs) != len(response.SelectedCaseIDs) {
				return checks, fmt.Errorf("invalid fixed case completion response")
			}
			expected, err := h.authorizedFixedCaseIDs(conversationID, dir, response.CatalogCaseIDs)
			if err != nil || strings.Join(expected, "\x00") != strings.Join(response.SelectedCaseIDs, "\x00") {
				return checks, fmt.Errorf("fixed case authorization scope mismatch")
			}
			if err := h.verifyFixedCaseRuntimeRecords(conversationID, &response.FixedCaseCompletion); err != nil {
				return checks, err
			}
			checks = append(checks, response.FixedCaseCompletion)
		}
		return checks, nil
	}
}

// Original successful init defines scope; edited metadata cannot shrink it.
func (h *AgentHandler) authorizedFixedCaseIDs(conversationID, dir string, catalog []string) ([]string, error) {
	rows, err := h.db.Query("SELECT id FROM tool_executions WHERE conversation_id = ? AND tool_name = ? AND status = ? ORDER BY start_time DESC", conversationID, "banma_pentest_run_cases", "completed")
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		e, err := h.db.GetToolExecution(id)
		if err != nil {
			return nil, err
		}
		if e.Arguments["mode"] != "init" || e.Result == nil || e.Result.IsError {
			continue
		}
		var result struct {
			OK     bool   `json:"ok"`
			RunDir string `json:"run_dir"`
		}
		if json.Unmarshal([]byte(mcp.ToolResultPlainText(e.Result)), &result) != nil || !result.OK || result.RunDir != dir {
			continue
		}
		payload, ok := e.Arguments["payload"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("init payload unavailable")
		}
		info, ok := payload["test_info"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("init scope unavailable")
		}
		selected, present := info["case_ids"]
		if !present {
			return catalog, nil
		}
		raw, err := json.Marshal(selected)
		if err != nil {
			return nil, err
		}
		var cases []string
		if json.Unmarshal(raw, &cases) != nil {
			return nil, fmt.Errorf("init case ids invalid")
		}
		return cases, nil
	}
	return nil, fmt.Errorf("matching successful init unavailable")
}

func (h *AgentHandler) verifyFixedCaseRuntimeRecords(conversationID string, check *agentfinalizer.FixedCaseCompletion) error {
	rows, err := h.db.Query("SELECT id FROM tool_executions WHERE conversation_id=? AND tool_name IN (?,?) AND status=? ORDER BY start_time DESC", conversationID, "banma_pentest_run_cases", "banma_report", "completed")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	verified := map[string]string{}
	for _, id := range ids {
		record, err := h.db.GetToolExecution(id)
		if err != nil {
			return err
		}
		if record.Result == nil || record.Result.IsError || record.Arguments["run_dir"] != check.RunDir {
			continue
		}
		if record.Arguments["mode"] != "save" && record.Arguments["mode"] != "check" {
			continue
		}
		for _, file := range record.Result.NativeFiles {
			if _, exists := verified[file.Path]; !exists {
				verified[file.Path] = file.SHA256
			}
		}
	}
	matches := func(path string) bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		sum := sha256.Sum256(data)
		return verified[path] == hex.EncodeToString(sum[:])
	}
	pending := map[string]bool{}
	for _, id := range check.PendingCaseIDs {
		pending[id] = true
	}
	for _, id := range check.SelectedCaseIDs {
		if !matches(filepath.Join(check.RunDir, "evidence", id+".json")) {
			pending[id] = true
		}
	}
	check.PendingCaseIDs = nil
	for _, id := range check.SelectedCaseIDs {
		if pending[id] {
			check.PendingCaseIDs = append(check.PendingCaseIDs, id)
		}
	}
	check.ValidSavedCount = len(check.SelectedCaseIDs) - len(check.PendingCaseIDs)
	if !matches(filepath.Join(check.RunDir, "evidence/report-check.json")) {
		check.ReportPending = true
	}
	return nil
}
