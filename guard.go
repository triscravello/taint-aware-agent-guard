package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	OutcomePass   = "pass"
	OutcomeDetect = "detect"
	OutcomeAsk    = "ask"
	OutcomeDeny   = "deny"
)

const (
	stateClean       = "clean"
	stateMissing     = "missing"
	stateCorrupt     = "corrupt"
	stateUnavailable = "unavailable"
)

type HookInput struct {
	SessionID     string         `json:"session_id"`
	CWD           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolResponse  any            `json:"tool_response,omitempty"`
	ToolUseID     string         `json:"tool_use_id,omitempty"`
}

type State struct {
	Version    int      `json:"version"`
	SessionKey string   `json:"session_key"`
	Tainted    bool     `json:"tainted"`
	Degraded   bool     `json:"degraded"`
	Sources    []string `json:"sources"`
	UpdatedAt  string   `json:"updated_at"`
}

type Decision struct {
	Outcome    string
	Reason     string
	Category   string
	Sensitive  bool
	Suspicious bool
}

type AuditRecord struct {
	Timestamp  string `json:"timestamp"`
	SessionKey string `json:"session_key"`
	Event      string `json:"event"`
	Tool       string `json:"tool"`
	Category   string `json:"category"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
}

type HookDecisionOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type HookOutput struct {
	HookSpecificOutput *HookDecisionOutput `json:"hookSpecificOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
}

func DefaultStateRoot() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "taintguard"), nil
}

func SessionKey(input HookInput) (string, bool) {
	raw := strings.TrimSpace(input.SessionID)
	fallback := false
	if raw == "" {
		fallback = true
		raw = "missing:" + strings.TrimSpace(input.CWD)
	}
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:]), fallback
}

func RunHook(inputFile, outputFile *os.File, root string) error {
	var input HookInput
	if err := json.NewDecoder(inputFile).Decode(&input); err != nil {
		return fmt.Errorf("decode hook input: %w", err)
	}

	switch input.HookEventName {
	case "PostToolUse":
		decision, err := Observe(root, input)
		if err != nil {
			return json.NewEncoder(outputFile).Encode(HookOutput{
				SystemMessage: "TaintGuard could not persist session state. Later recognized sensitive actions will use conservative handling.",
			})
		}
		if decision.Suspicious {
			return json.NewEncoder(outputFile).Encode(HookOutput{
				SystemMessage: "TaintGuard detected an untrusted source for this session. Detection alone does not deny a later action.",
			})
		}
		return nil
	case "PreToolUse":
		decision := Decide(root, input)
		if decision.Outcome == OutcomePass {
			return nil
		}
		return json.NewEncoder(outputFile).Encode(HookOutput{
			HookSpecificOutput: &HookDecisionOutput{
				HookEventName:            "PreToolUse",
				PermissionDecision:       decision.Outcome,
				PermissionDecisionReason: decision.Reason,
			},
		})
	default:
		return fmt.Errorf("unsupported hook event %q", input.HookEventName)
	}
}

func Observe(root string, input HookInput) (Decision, error) {
	key, fallback := SessionKey(input)
	state, status := loadState(root, input)
	source, suspicious := untrustedSource(input.ToolName)

	if status == stateCorrupt || status == stateUnavailable {
		if !suspicious {
			return Decision{Outcome: OutcomeDetect, Reason: "state is degraded", Category: "state", Suspicious: true}, fmt.Errorf("existing state is %s", status)
		}
		state = State{Version: 1, SessionKey: key, Degraded: true}
	}
	if status == stateMissing {
		state = State{Version: 1, SessionKey: key}
	}
	if fallback {
		state.Degraded = true
	}

	decision := Decision{Outcome: OutcomePass, Reason: "trusted source observed", Category: "source"}
	if suspicious {
		state.Tainted = true
		state.Sources = appendUnique(state.Sources, source)
		decision = Decision{
			Outcome:    OutcomeDetect,
			Reason:     "untrusted source observed after successful tool use",
			Category:   "source",
			Suspicious: true,
		}
	}
	state.Version = 1
	state.SessionKey = key
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	if err := saveState(root, state); err != nil {
		return decision, err
	}
	if err := appendAudit(root, input, key, decision); err != nil {
		return decision, err
	}
	return decision, nil
}

func Decide(root string, input HookInput) Decision {
	key, fallback := SessionKey(input)
	state, status := loadState(root, input)
	category, sensitive, highRisk := classifySensitive(input)
	degraded := fallback || status != stateClean || state.Degraded

	decision := Decision{
		Outcome:   OutcomePass,
		Reason:    "no additional TaintGuard decision; normal Claude Code permissions still apply",
		Category:  category,
		Sensitive: sensitive,
	}

	if sensitive {
		switch {
		case highRisk && (state.Tainted || degraded):
			decision.Outcome = OutcomeDeny
			decision.Reason = "denied simulated credential egress because the session is tainted or state is degraded"
		case state.Tainted:
			decision.Outcome = OutcomeAsk
			decision.Reason = "user approval required because this sensitive action follows untrusted content"
		case degraded:
			decision.Outcome = OutcomeAsk
			decision.Reason = "user approval required because session state is missing, corrupt, unavailable, or using the fallback key"
		}
	}

	_ = appendAudit(root, input, key, decision)
	return decision
}

func untrustedSource(tool string) (string, bool) {
	switch tool {
	case "WebFetch", "WebSearch":
		return tool, true
	default:
		if strings.HasPrefix(tool, "mcp__") {
			return tool, true
		}
		return "", false
	}
}

func classifySensitive(input HookInput) (string, bool, bool) {
	switch input.ToolName {
	case "Read":
		path := strings.ToLower(mapString(input.ToolInput, "file_path"))
		base := filepath.Base(path)
		if base == ".env" || strings.Contains(base, "dummy-credentials") || strings.Contains(base, "id_rsa") {
			return "credential-read", true, false
		}
	case "Bash":
		command := strings.ToLower(mapString(input.ToolInput, "command"))
		hasNetworkSim := strings.Contains(command, "network-sim")
		hasDummyCredential := strings.Contains(command, "dummy-credentials")
		switch {
		case hasNetworkSim && hasDummyCredential:
			return "simulated-credential-egress", true, true
		case hasNetworkSim:
			return "simulated-network-egress", true, false
		case hasDummyCredential:
			return "credential-read-via-shell", true, false
		}
	}
	return "ordinary", false, false
}

func mapString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}

func loadState(root string, input HookInput) (State, string) {
	key, fallback := SessionKey(input)
	state := State{Version: 1, SessionKey: key, Degraded: fallback}
	data, err := os.ReadFile(statePath(root, key))
	if err != nil {
		if os.IsNotExist(err) {
			return state, stateMissing
		}
		state.Degraded = true
		return state, stateUnavailable
	}
	if err := json.Unmarshal(data, &state); err != nil {
		state = State{Version: 1, SessionKey: key, Degraded: true}
		return state, stateCorrupt
	}
	if state.Version != 1 || state.SessionKey != key {
		state = State{Version: 1, SessionKey: key, Degraded: true}
		return state, stateCorrupt
	}
	if fallback {
		state.Degraded = true
	}
	return state, stateClean
}

func saveState(root string, state State) error {
	dir := filepath.Join(root, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	temp, err := os.CreateTemp(dir, "state-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, statePath(root, state.SessionKey))
}

func appendAudit(root string, input HookInput, key string, decision Decision) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(root, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	record := AuditRecord{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		SessionKey: key,
		Event:      input.HookEventName,
		Tool:       input.ToolName,
		Category:   decision.Category,
		Outcome:    decision.Outcome,
		Reason:     decision.Reason,
	}
	return json.NewEncoder(file).Encode(record)
}

func statePath(root, key string) string {
	return filepath.Join(root, "state", key+".json")
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
