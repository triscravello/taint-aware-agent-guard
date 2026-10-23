package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Scenario struct {
	Name     string      `json:"name"`
	Class    string      `json:"class"`
	Events   []HookInput `json:"events"`
	Expected string      `json:"expected"`
}

type ScenarioResult struct {
	Name     string
	Class    string
	Expected string
	Actual   string
}

type Metrics struct {
	AttackTotal       int
	DeniedAttacks     int
	ApprovalGated     int
	MissedAttacks     int
	BenignTotal       int
	BenignPasses      int
	FalsePositives    int
	ExpectationMisses int
}

func ReplayFile(path string, output *os.File) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var scenarios []Scenario
	if err := json.Unmarshal(data, &scenarios); err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "taintguard-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)

	results, metrics, err := EvaluateScenarios(scenarios, root)
	if err != nil {
		return err
	}
	printEvaluation(output, results, metrics)
	if metrics.ExpectationMisses != 0 {
		return fmt.Errorf("%d scenario expectations did not match", metrics.ExpectationMisses)
	}
	return nil
}

func EvaluateScenarios(scenarios []Scenario, root string) ([]ScenarioResult, Metrics, error) {
	results := make([]ScenarioResult, 0, len(scenarios))
	metrics := Metrics{}

	for index, scenario := range scenarios {
		scenarioRoot := filepath.Join(root, fmt.Sprintf("%02d", index))
		if err := os.MkdirAll(scenarioRoot, 0o700); err != nil {
			return nil, Metrics{}, err
		}
		actual := OutcomePass
		sawPreToolUse := false
		for _, event := range scenario.Events {
			switch event.HookEventName {
			case "PostToolUse":
				if _, err := Observe(scenarioRoot, event); err != nil {
					return nil, Metrics{}, fmt.Errorf("scenario %q observation: %w", scenario.Name, err)
				}
			case "PreToolUse":
				sawPreToolUse = true
				actual = Decide(scenarioRoot, event).Outcome
			default:
				return nil, Metrics{}, fmt.Errorf("scenario %q has unsupported event %q", scenario.Name, event.HookEventName)
			}
		}
		if !sawPreToolUse {
			return nil, Metrics{}, fmt.Errorf("scenario %q has no PreToolUse event", scenario.Name)
		}

		result := ScenarioResult{Name: scenario.Name, Class: scenario.Class, Expected: scenario.Expected, Actual: actual}
		results = append(results, result)
		if actual != scenario.Expected {
			metrics.ExpectationMisses++
		}

		switch scenario.Class {
		case "attack":
			metrics.AttackTotal++
			switch actual {
			case OutcomeDeny:
				metrics.DeniedAttacks++
			case OutcomeAsk:
				metrics.ApprovalGated++
			default:
				metrics.MissedAttacks++
			}
		case "benign":
			metrics.BenignTotal++
			if actual == OutcomePass {
				metrics.BenignPasses++
			} else {
				metrics.FalsePositives++
			}
		default:
			return nil, Metrics{}, fmt.Errorf("scenario %q has unknown class %q", scenario.Name, scenario.Class)
		}
	}
	return results, metrics, nil
}

func printEvaluation(output *os.File, results []ScenarioResult, metrics Metrics) {
	fmt.Fprintln(output, "# Deterministic Replay Evaluation")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "| Scenario | Class | Expected | Actual |")
	fmt.Fprintln(output, "| --- | --- | --- | --- |")
	for _, result := range results {
		fmt.Fprintf(output, "| %s | %s | %s | %s |\n", result.Name, result.Class, result.Expected, result.Actual)
	}
	fmt.Fprintln(output)
	fmt.Fprintf(output, "- Denied attacks: %d/%d\n", metrics.DeniedAttacks, metrics.AttackTotal)
	fmt.Fprintf(output, "- Approval-gated attacks: %d/%d\n", metrics.ApprovalGated, metrics.AttackTotal)
	fmt.Fprintf(output, "- Missed attacks: %d/%d\n", metrics.MissedAttacks, metrics.AttackTotal)
	fmt.Fprintf(output, "- False-negative rate: %.2f%%\n", rate(metrics.MissedAttacks, metrics.AttackTotal))
	fmt.Fprintf(output, "- Benign passes: %d/%d\n", metrics.BenignPasses, metrics.BenignTotal)
	fmt.Fprintf(output, "- False positives: %d/%d\n", metrics.FalsePositives, metrics.BenignTotal)
	fmt.Fprintf(output, "- False-positive rate: %.2f%%\n", rate(metrics.FalsePositives, metrics.BenignTotal))
	fmt.Fprintf(output, "- Expectation mismatches: %d\n", metrics.ExpectationMisses)
}

func rate(count, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) * 100 / float64(total)
}
