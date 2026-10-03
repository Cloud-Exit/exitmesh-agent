package deploytest

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRequiredInventoryCoverage(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed")
	}
	type scope struct {
		Key    string `json:"key"`
		State  string `json:"state"`
		Reason string `json:"reason,omitempty"`
	}
	complete := []scope{{"Secret|", "complete", ""}, {"ConfigMap|", "complete", ""}, {"inventory.exitmesh.io/CustomResourceDiscovery|", "complete", ""}}
	check := func(t *testing.T, scopes []scope, want bool) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"targets": []any{map[string]any{"last_health": map[string]any{"coverage": scopes}}}})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(jq, "-e", "-f", filepath.Join(repoRoot(t), ".github/scripts/required-inventory-coverage.jq"))
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.CombinedOutput()
		if (err == nil) != want {
			t.Fatalf("coverage accepted=%v, want %v: %s", err == nil, want, out)
		}
	}
	t.Run("complete", func(t *testing.T) { check(t, complete, true) })
	t.Run("absent", func(t *testing.T) { check(t, nil, false) })
	for i, s := range complete {
		t.Run(s.Key, func(t *testing.T) {
			missing := append([]scope{}, complete[:i]...)
			missing = append(missing, complete[i+1:]...)
			check(t, missing, false)
			for _, state := range []string{"partial", "unavailable"} {
				failed := append([]scope{}, complete...)
				failed[i].State, failed[i].Reason = state, "406 Not Acceptable"
				check(t, failed, false)
			}
		})
	}
	t.Run("namespace scopes", func(t *testing.T) {
		scopes := append([]scope{}, complete...)
		scopes[0].Key = "Secret|a"
		scopes = append(scopes, scope{"Secret|b", "complete", ""})
		check(t, scopes, true)
		scopes[3].State = "unavailable"
		check(t, scopes, false)
	})
}
