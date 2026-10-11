package banma

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var decisionFence = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*?\\})\\s*```")

// Some Eino configurations prefix the final JSON with a short introduction.
// Extract the single JSON payload, then validate its clauses and actual sources.
func ParseDecision(raw string) (Decision, error) {
	var out Decision
	raw = strings.TrimSpace(raw)
	if block := decisionFence.FindStringSubmatch(raw); len(block) == 2 {
		raw = block[1]
	}
	if json.Unmarshal([]byte(raw), &out) != nil {
		return out, fmt.Errorf("Eino judgment is not the requested object")
	}
	if len(out.Checks) == 0 && len(out.Gaps) == 0 {
		return out, fmt.Errorf("empty judgment")
	}
	return out, nil
}
