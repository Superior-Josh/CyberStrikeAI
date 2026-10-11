package banma

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type LoadBudget struct {
	Baseline       int `json:"baseline_requests"`
	Timeout        int `json:"timeout_seconds"`
	Recovery       int `json:"recovery_requests"`
	RecoveryWindow int `json:"recovery_window_seconds"`
	Phases         []struct {
		Concurrency int `json:"concurrency"`
		Requests    int `json:"requests"`
	} `json:"phases"`
}

func (r *Runner) controlledLoad(ctx context.Context, in Input, g map[string]interface{}) (Decision, bool, error) {
	c, _ := g["case"].(map[string]interface{})
	value, exists := c["load_budget"]
	if !exists || len(in.Targets) != 1 {
		return Decision{}, false, nil
	}
	raw, _ := json.Marshal(value)
	var budget LoadBudget
	if err := json.Unmarshal(raw, &budget); err != nil {
		return Decision{}, true, err
	}
	if budget.Baseline < 1 || budget.Timeout < 1 || budget.Recovery < 1 || budget.RecoveryWindow < 1 || len(budget.Phases) == 0 {
		return Decision{}, true, fmt.Errorf("load_budget missing positive values")
	}
	for _, phase := range budget.Phases {
		if phase.Concurrency < 1 || phase.Requests < phase.Concurrency {
			return Decision{}, true, fmt.Errorf("invalid load phase")
		}
	}
	target := in.Targets[0]
	baselineStatus := 0
	sample := func(callCtx context.Context) (Capture, error) {
		e, err := r.request(callCtx, "PT_WEB_11", target, "GET", nil, "", budget.Timeout)
		if e != nil && e.Result != nil && len(e.Result.NativeFiles) == 1 {
			capture, readErr := ReadCapture(e)
			if readErr != nil {
				return Capture{}, readErr
			}
			return capture, err
		}
		if err == nil {
			err = fmt.Errorf("native load capture missing")
		}
		return Capture{}, err
	}
	for n := 0; n < budget.Baseline; n++ {
		capture, err := sample(ctx)
		if err != nil {
			return Decision{}, true, err
		}
		if n == 0 {
			baselineStatus = capture.Status
		}
		if capture.Status != baselineStatus || capture.Status < 200 || capture.Status >= 400 {
			return Decision{}, true, fmt.Errorf("normal availability baseline is not stable")
		}
	}
	stopped := false
	gaps := []string{}
	for _, phase := range budget.Phases {
		var next atomic.Int64
		var stop atomic.Bool
		var done atomic.Int64
		var wg sync.WaitGroup
		for worker := 0; worker < phase.Concurrency; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() && ctx.Err() == nil {
					n := next.Add(1)
					if n > int64(phase.Requests) {
						return
					}
					capture, err := sample(ctx)
					done.Add(1)
					if err != nil || capture.Status != baselineStatus || capture.Status >= 500 {
						stop.Store(true)
						return
					}
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return Decision{}, true, ctx.Err()
		}
		if stop.Load() {
			stopped = true
			gaps = append(gaps, "负载请求异常，已停止新增提交并等待在途结束；未完整达到计划负载")
			break
		}
		if done.Load() != int64(phase.Requests) {
			return Decision{}, true, fmt.Errorf("load phase count mismatch")
		}
	}
	ended := time.Now()
	recoveryGood := true
	recoveryServerErrors := 0
	for n := 0; n < budget.Recovery; n++ {
		capture, err := sample(ctx)
		if err != nil || capture.Status != baselineStatus || capture.Status >= 500 {
			recoveryGood = false
		}
		if err == nil && capture.Status >= 500 {
			recoveryServerErrors++
		}
	}
	if time.Since(ended) > time.Duration(budget.RecoveryWindow)*time.Second {
		gaps = append(gaps, "恢复复核未在原文窗口内结束")
	}
	indices := []int{}
	for i := range r.captures {
		indices = append(indices, i)
	}
	if !recoveryGood && recoveryServerErrors == budget.Recovery {
		return Decision{Method: "code", Checks: []Check{{Ref: "steps[4]", Result: "失败", Reason: "停止负载后规定复核仍观察到请求异常或与正常基线不一致，原文保留", Evidence: indices}}, Gaps: append(gaps, "其他负载影响条款及故障归因待核验"), Recovery: "待确认"}, true, nil
	}
	if !recoveryGood {
		gaps = append(gaps, "恢复样本存在工具/传输异常或响应变化，尚不能据此证明持续目标故障")
	}
	if stopped || len(gaps) > 0 {
		recoveryState := "已恢复"
		if !recoveryGood {
			recoveryState = "待确认"
		}
		return Decision{Gaps: gaps, Recovery: recoveryState, RecoveryEvidence: indices}, true, nil
	}
	return Decision{Method: "code", Checks: CompleteChecks(g, "通过", "代码以原文预算运行固定正常样本、限定工作数的并发请求及停止后恢复复核；计数与真实原文对应，范围仅限所选HTTP入口", indices), Recovery: "已恢复", RecoveryEvidence: indices}, true, nil
}
