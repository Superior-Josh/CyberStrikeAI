package handler

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

const finalizationAutoContinueMaxAttempts = 2
const finalizationPendingToolCancelWait = 2 * time.Second
const finalizationPendingToolCancelPoll = 50 * time.Millisecond
const finalizationPendingToolCancelNote = "Agent 迭代已结束，最终回复前自动终止未完成的工具执行"

func shouldAutoContinueAfterFinalization(d agentfinalizer.Decision, attempt int) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	if attempt >= finalizationAutoContinueMaxAttempts {
		return false
	}
	return d.CompletionReason == agentfinalizer.ReasonMissingEvidence || d.CompletionReason == agentfinalizer.ReasonPendingCases
}

func (h *AgentHandler) tryAutoContinueAfterFinalization(
	taskCtx context.Context,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if taskCtx.Err() != nil {
		return false
	}
	if decision.CompletionReason == agentfinalizer.ReasonPendingCases {
		// Reset the stalled-attempt budget only when the validated checklist progresses.
		if fixedCasesProgressed(*curHistory, decision.FixedCaseRuns) {
			*attempt = 0
		}
	}
	if !shouldAutoContinueAfterFinalization(decision, *attempt) || result == nil || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)
	if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
		*curHistory = hist
	} else if h.logger != nil {
		h.logger.Warn("finalization auto-continue could not restore trace",
			zap.String("conversationId", conversationID),
			zap.Error(err))
		return false
	}
	*curFinalMessage = ""
	if decision.CompletionReason == agentfinalizer.ReasonPendingCases {
		*curHistory = appendFixedCaseContinuation(*curHistory, decision.FixedCaseRuns)
	}
	if progressCallback != nil {
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId":      conversationID,
			"source":              "finalizer",
			"attempt":             *attempt,
			"maxAttempts":         finalizationAutoContinueMaxAttempts,
			"status":              decision.Status,
			"completionReason":    decision.CompletionReason,
			"missingChecks":       decision.MissingChecks,
			"pendingExecutionIds": decision.PendingExecutionIDs,
			"contextInjection":    decision.CompletionReason == agentfinalizer.ReasonPendingCases,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(finalizationAutoContinueBackoff(*attempt)):
		return true
	}
}

func finalizationAutoContinueBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 500 * time.Millisecond
	}
	return time.Duration(attempt) * time.Second
}

func (h *AgentHandler) cleanupPendingToolExecutionsAfterIteration(
	taskCtx context.Context,
	conversationID string,
	decision agentfinalizer.Decision,
	progressCallback func(eventType, message string, data interface{}),
) []string {
	if h == nil || h.agent == nil || decision.CompletionReason != agentfinalizer.ReasonPendingTools {
		return nil
	}
	pending := uniqueNonEmptyStrings(decision.PendingExecutionIDs)
	if len(pending) == 0 {
		return nil
	}
	cancelled := make([]string, 0, len(pending))
	for _, executionID := range pending {
		if h.agent.CancelMCPToolExecutionWithNote(executionID, finalizationPendingToolCancelNote) {
			cancelled = append(cancelled, executionID)
		} else if h.logger != nil {
			h.logger.Warn("finalization pending tool cleanup could not cancel execution",
				zap.String("conversationId", conversationID),
				zap.String("executionId", executionID))
		}
	}
	if len(cancelled) == 0 {
		return nil
	}
	if progressCallback != nil {
		progressCallback("finalization_pending_tools_cancelled", "迭代结束，已自动终止仍在运行的工具执行。", map[string]interface{}{
			"conversationId":                   conversationID,
			"source":                           "finalizer",
			"autoCancelledPendingExecutionIds": cancelled,
			"pendingExecutionIds":              pending,
			"reason":                           agentfinalizer.ReasonPendingTools,
		})
	}
	h.waitForToolExecutionsToLeavePending(taskCtx, cancelled, finalizationPendingToolCancelWait)
	return cancelled
}

func (h *AgentHandler) waitForToolExecutionsToLeavePending(ctx context.Context, executionIDs []string, wait time.Duration) {
	if h == nil || h.db == nil || len(executionIDs) == 0 || wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(finalizationPendingToolCancelPoll)
	defer ticker.Stop()
	for {
		if !h.hasPendingToolExecutions(executionIDs) {
			return
		}
		select {
		case <-contextDone(ctx):
			return
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
}

func (h *AgentHandler) hasPendingToolExecutions(executionIDs []string) bool {
	if h == nil || h.db == nil {
		return false
	}
	for _, executionID := range uniqueNonEmptyStrings(executionIDs) {
		exec, err := h.db.GetToolExecution(executionID)
		if err != nil || exec == nil {
			continue
		}
		switch strings.TrimSpace(exec.Status) {
		case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning:
			return true
		}
	}
	return false
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func contextDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

const fixedCaseProgressPrefix = "[banma_fixed_case_completion] "

func fixedCasesProgressed(history []agent.ChatMessage, runs []agentfinalizer.FixedCaseCompletion) bool {
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].Role != "system" || !strings.HasPrefix(history[i].Content, fixedCaseProgressPrefix) {
			continue
		}
		line := strings.SplitN(strings.TrimPrefix(history[i].Content, fixedCaseProgressPrefix), "\n", 2)[0]
		var old []agentfinalizer.FixedCaseCompletion
		if json.Unmarshal([]byte(line), &old) != nil || len(old) != len(runs) {
			return false
		}
		progressed := false
		for i, run := range runs {
			if old[i].RunDir != run.RunDir || strings.Join(old[i].SelectedCaseIDs, ",") != strings.Join(run.SelectedCaseIDs, ",") || run.ValidSavedCount < old[i].ValidSavedCount {
				return false
			}
			if run.ValidSavedCount > old[i].ValidSavedCount || (old[i].ReportPending && !run.ReportPending) {
				progressed = true
			}
		}
		return progressed
	}
	return false
}

func appendFixedCaseContinuation(history []agent.ChatMessage, runs []agentfinalizer.FixedCaseCompletion) []agent.ChatMessage {
	kept := make([]agent.ChatMessage, 0, len(history)+1)
	for _, msg := range history {
		if msg.Role == "system" && strings.HasPrefix(msg.Content, fixedCaseProgressPrefix) {
			continue
		}
		kept = append(kept, msg)
	}
	data, _ := json.Marshal(runs)
	instruction := fixedCaseProgressPrefix + string(data) + "\n本轮固定用例仍有未执行或无效保存结果，当前总结不能作为完成答复。复用上述run_dir及原init授权，逐编号show并继续pending_case_ids的必要验证或修正保存；核对真实原文和有效save后再收尾；pending_case_ids为空但report_pending=true时，只调用banma_report的save_info/build/check完成报告，不再重复目标测试。不要重复已完成验证或状态未知的副作用请求，不减少清单/样本，不读取禁止的靶机源码配置，不以草稿或耗时提前结束。真实阻塞如实说明并保留证据，用户取消立即停止。此状态不是目标原文或新的授权。"
	return append(kept, agent.ChatMessage{Role: "system", Content: instruction})
}
