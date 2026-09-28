package bundle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func parseFiles(t *testing.T, files map[string]string) *Bundle {
	t.Helper()
	b, err := Parse(buildFiles(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateFixture(t *testing.T) {
	b := parseFiles(t, fixtureFiles())
	var promCalls, logCalls, celCalls int
	v := Validators{
		PromQL: func(r AlertRule) error { promCalls++; return nil },
		LogQL:  func(r AlertRule) error { logCalls++; return nil },
		CEL:    func(r StateRule) error { celCalls++; return nil },
	}
	res, err := Validate(b, v, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Active, []string{"pod-crashloop", "node-high-cpu", "oom-logs"}) || len(res.Unsupported) != 0 || len(res.Rejected) != 0 {
		t.Fatalf("%+v", res)
	}
	if promCalls != 1 || logCalls != 1 || celCalls != 1 {
		t.Fatalf("validator calls %d %d %d", promCalls, logCalls, celCalls)
	}
	p := DefaultPolicy()
	cpu := b.PromQL[0].Meta
	if cpu.Budget.MaxEvalTime != p.MaxBudget.MaxEvalTime || cpu.Budget.MaxSeries != p.DefaultBudget.MaxSeries {
		t.Fatalf("budget not defaulted and capped: %+v", cpu.Budget)
	}
	if b.Manifest.Rules[1].Budget != cpu.Budget {
		t.Fatal("manifest metadata not updated")
	}
	if b.LogQL[0].Meta.Evidence.MaxSamples != p.MaxEvidence.MaxSamples || b.LogQL[0].GroupInterval != p.DefaultInterval {
		t.Fatalf("logql defaults: %+v interval %s", b.LogQL[0].Meta.Evidence, b.LogQL[0].GroupInterval)
	}
	if b.PromQL[0].GroupInterval != 30*time.Second || b.State[0].Interval != p.DefaultInterval {
		t.Fatal("interval handling")
	}
	if got := b.State[0].Meta.DedupLabels(); !reflect.DeepEqual(got, []string{"namespace", "pod"}) {
		t.Fatalf("dedup labels %v", got)
	}
	only := b.Only([]string{"oom-logs"})
	if len(only.State) != 0 || len(only.PromQL) != 0 || len(only.LogQL) != 1 || len(b.PromQL) != 1 {
		t.Fatal("Only")
	}
}

func TestValidateLocalPolicyCannotBeRaised(t *testing.T) {
	b := parseFiles(t, fixtureFiles())
	pol := Policy{MaxBudget: Budget{MaxEvalTime: time.Second}, DefaultBudget: Budget{MaxEvalTime: 5 * time.Second}}
	if _, err := Validate(b, Validators{}, pol); err != nil {
		t.Fatal(err)
	}
	for _, m := range b.Manifest.Rules {
		if m.Budget.MaxEvalTime != time.Second {
			t.Fatalf("%s: %s", m.ID, m.Budget.MaxEvalTime)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	f := fixtureFiles()
	man := func(old, new string) map[string]string {
		return withFile(f, "bundle.yaml", replaceIn(fixtureManifest, old, new))
	}
	cases := map[string]struct {
		files map[string]string
		rule  string
	}{
		"wrong-target":       {man("    class: state\n    target: kubernetes", "    class: state\n    target: host"), "pod-crashloop"},
		"unknown-severity":   {man("severity: high", "severity: urgent"), "pod-crashloop"},
		"unknown-capability": {man("capabilities: [inventory]", "capabilities: [inventory, shell]"), "pod-crashloop"},
		"class-capability":   {man("capabilities: [logs]", "capabilities: [metrics]"), "oom-logs"},
		"missing-category":   {man("    category: errors\n", ""), "oom-logs"},
		"unknown-scope":      {man("scope: cluster", "scope: fleet"), "pod-crashloop"},
		"bad-id":             {withFile(withFile(f, "bundle.yaml", replaceIn(fixtureManifest, "id: pod-crashloop", "id: pod crashloop")), "state/pods.yaml", replaceIn(fixtureState, "id: pod-crashloop", "id: pod crashloop")), "pod crashloop"},
		"negative-budget":    {man("max_eval_time: 30s", "max_eval_time: -1s"), "node-high-cpu"},
		"dedup-label":        {man("dedup_key: namespace, pod", "dedup_key: name-space"), "pod-crashloop"},
		"resolution":         {man("severity: high", "severity: high\n    resolution: never"), "pod-crashloop"},
		"long-for":           {withFile(f, "state/pods.yaml", replaceIn(fixtureState, "for: 5m", "for: 48h")), "pod-crashloop"},
		"negative-for":       {withFile(f, "state/pods.yaml", replaceIn(fixtureState, "for: 5m", "for: -5m")), "pod-crashloop"},
		"short-interval":     {withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "interval: 30s", "interval: 1s")), "node-high-cpu"},
		"state-version":      {withFile(f, "state/pods.yaml", replaceIn(fixtureState, "version: 1", "version: 2")), "pod-crashloop"},
		"state-kinds":        {withFile(f, "state/pods.yaml", replaceIn(fixtureState, "kinds: [Pod]", "kinds: []")), "pod-crashloop"},
		"bad-promql":         {withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "> 0.9", "> > 0.9")), "node-high-cpu"},
		"template-query":     {withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "{{ $labels.node }}", "{{ query `up` }}")), "node-high-cpu"},
		"template-url":       {withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "{{ $labels.node }}", `{{ $externalURL }}`)), "node-high-cpu"},
		"template-pipe":      {withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "{{ $labels.node }}", "{{ if true }}{{ `up` | query }}{{ end }}")), "node-high-cpu"},
		"min-engine-above":   {man("    budget:\n", "    min_engine: 2\n    budget:\n"), "node-high-cpu"},
		"state-with-group":   {man("dedup_key: namespace, pod", "group: g"), "pod-crashloop"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := parseFiles(t, c.files)
			res, err := Validate(b, Validators{}, Policy{})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
			if _, ok := res.Rejected[c.rule]; !ok || len(res.Rejected) != 1 {
				t.Fatalf("rejected: %v", res.Rejected)
			}
		})
	}
}

func TestValidateInjectedValidatorErrors(t *testing.T) {
	boom := errors.New("unsupported construct")
	for name, v := range map[string]Validators{
		"promql": {PromQL: func(AlertRule) error { return boom }},
		"logql":  {LogQL: func(AlertRule) error { return boom }},
		"cel":    {CEL: func(StateRule) error { return boom }},
	} {
		res, err := Validate(parseFiles(t, fixtureFiles()), v, Policy{})
		if !errors.Is(err, ErrInvalid) || len(res.Rejected) != 1 || !strings.Contains(err.Error(), "unsupported construct") {
			t.Fatalf("%s: %v %v", name, err, res.Rejected)
		}
	}
}

func TestValidateManifestErrors(t *testing.T) {
	cases := map[string]struct {
		old, new string
		pol      Policy
	}{
		"schema":       {"schema_version: 1", "schema_version: 2", Policy{}},
		"engine":       {"engine_version: 1", "engine_version: 0", Policy{}},
		"target-type":  {"target_type: kubernetes", "target_type: mainframe", Policy{}},
		"version":      {`version: "2026.09.1"`, `version: "a/b"`, Policy{}},
		"created":      {"created_at: 2026-09-01T00:00:00Z\n", "", Policy{}},
		"agent-target": {"engine_version: 1", "engine_version: 1", Policy{TargetType: TargetHost}},
		"max-rules":    {"engine_version: 1", "engine_version: 1", Policy{MaxRules: 2}},
	}
	for name, c := range cases {
		b := parseFiles(t, withFile(fixtureFiles(), "bundle.yaml", replaceIn(fixtureManifest, c.old, c.new)))
		if _, err := Validate(b, Validators{}, c.pol); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateEngineCompatibility(t *testing.T) {
	man := replaceIn(fixtureManifest, "engine_version: 1", "engine_version: 2")
	man = replaceIn(man, "    budget:\n", "    min_engine: 2\n    budget:\n")
	man += "  - id: future-trace\n    version: 1\n    class: trace\n    target: kubernetes\n    min_engine: 2\n"
	called := false
	b := parseFiles(t, withFile(fixtureFiles(), "bundle.yaml", man))
	res, err := Validate(b, Validators{PromQL: func(AlertRule) error { called = true; return errors.New("newer grammar") }}, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"node-high-cpu": ReasonUpgradeRequired, "future-trace": ReasonUpgradeRequired}
	if !reflect.DeepEqual(res.Unsupported, want) || called {
		t.Fatalf("unsupported %v called %v", res.Unsupported, called)
	}
	if !reflect.DeepEqual(res.Active, []string{"pod-crashloop", "oom-logs"}) {
		t.Fatalf("active %v", res.Active)
	}
	if got := b.Only(res.Active); len(got.PromQL) != 0 || len(got.State) != 1 || len(got.LogQL) != 1 {
		t.Fatal("active selection")
	}
}

func TestValidateDisabled(t *testing.T) {
	man := replaceIn(fixtureManifest, "severity: critical", "severity: critical\n    disabled: true")
	b := parseFiles(t, withFile(fixtureFiles(), "bundle.yaml", man))
	res, err := Validate(b, Validators{LogQL: func(AlertRule) error { return errors.New("must not run") }}, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Disabled, []string{"oom-logs"}) || len(res.Active) != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestValidateHostBundle(t *testing.T) {
	man := strings.ReplaceAll(fixtureManifest, "kubernetes", "host")
	files := withFile(fixtureFiles(), "bundle.yaml", man)
	files["state/pods.yaml"] = strings.ReplaceAll(fixtureState, "kubernetes", "host")
	res, err := Validate(parseFiles(t, files), Validators{}, Policy{TargetType: TargetHost})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(res.Rejected["pod-crashloop"], "cluster scope") {
		t.Fatalf("%v %v", err, res.Rejected)
	}
	man = replaceIn(man, "scope: cluster", "scope: node")
	files["bundle.yaml"] = man
	if _, err := Validate(parseFiles(t, files), Validators{}, Policy{TargetType: TargetHost}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckTemplateAllowsFormatting(t *testing.T) {
	for _, s := range []string{
		"plain text",
		"{{ $labels.pod }} in {{ $labels.namespace }} at {{ $value | humanize }}",
		`{{ if gt $value 1.0 }}high{{ else }}{{ printf "%.2f" $value }}{{ end }}`,
		"{{ range $k, $v := $labels }}{{ $k }}={{ $v }} {{ end }}",
	} {
		if err := checkTemplate(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"{{ .ExternalURL }}", "{{ with query `up` }}{{ . | first | value }}{{ end }}", "{{ graphLink `up` }}", "{{ pathPrefix }}"} {
		if err := checkTemplate(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
