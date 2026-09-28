package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"
)

// instance is one alert instance with Prometheus AlertingRule state.
type instance struct {
	Key             string            `json:"key"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	Summary         string            `json:"summary,omitempty"`
	Resources       []string          `json:"resources,omitempty"`
	Kind            string            `json:"kind,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	Value           jsonFloat         `json:"value"`
	Firing          bool              `json:"firing"`
	ActiveAt        time.Time         `json:"active_at"`
	FiredAt         time.Time         `json:"fired_at"`
	KeepFiringSince time.Time         `json:"keep_firing_since"`
	LastEval        time.Time         `json:"last_eval"`
	Stale           bool              `json:"stale,omitempty"`
	Flagged         bool              `json:"flagged,omitempty"`
}

// observation is one instance for which the rule condition holds at this evaluation.
type observation struct {
	key         string
	labels      map[string]string
	annotations map[string]string
	summary     string
	value       float64
	resources   []string
	kind        string
	namespace   string
}

// evalInput is one evaluation's outcome; keys neither observed nor incomplete are confirmed false.
type evalInput struct {
	observed       []observation
	incomplete     map[string]bool
	incompleteRest bool
	flagged        bool
	reason         string
}

type transition struct {
	kind       string
	inst       instance
	resolvedAt time.Time
	incomplete bool
}

type alertSet struct {
	active map[string]*instance
}

func newAlertSet() *alertSet { return &alertSet{active: map[string]*instance{}} }

func (a *alertSet) counts() (pending, firing int) {
	for _, i := range a.active {
		if i.Firing {
			firing++
		} else {
			pending++
		}
	}
	return
}

func (a *alertSet) sortedKeys() []string {
	keys := make([]string, 0, len(a.active))
	for k := range a.active {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// eval mirrors Prometheus AlertingRule.Eval; incomplete keys mark firing instances stale, never resolved.
func (a *alertSet) eval(ts time.Time, holdFor, keepFor time.Duration, in evalInput) ([]transition, error) {
	obs := make(map[string]*observation, len(in.observed))
	for i := range in.observed {
		o := &in.observed[i]
		if _, dup := obs[o.key]; dup {
			return nil, fmt.Errorf("vector contains metrics with the same labelset after applying alert labels: %s", o.key)
		}
		obs[o.key] = o
	}
	for k, o := range obs {
		if _, ok := a.active[k]; !ok {
			a.active[k] = &instance{Key: k, ActiveAt: ts, Kind: o.kind, Namespace: o.namespace}
		}
	}
	var out []transition
	emit := func(kind string, i *instance, incomplete bool) {
		t := transition{kind: kind, inst: *i, incomplete: incomplete}
		if kind == TransitionResolved {
			t.resolvedAt = ts
		}
		out = append(out, t)
	}
	for _, k := range a.sortedKeys() {
		i := a.active[k]
		if o, ok := obs[k]; ok {
			changed := i.Firing && (i.Stale || i.Flagged != in.flagged || i.Summary != o.summary ||
				!maps.Equal(i.Annotations, o.annotations) || !maps.Equal(i.Labels, o.labels) || !slices.Equal(i.Resources, o.resources))
			i.Labels, i.Annotations, i.Summary, i.Resources, i.Value = o.labels, o.annotations, o.summary, o.resources, jsonFloat(o.value)
			i.KeepFiringSince, i.Stale, i.LastEval = time.Time{}, false, ts
			switch {
			case !i.Firing && ts.Sub(i.ActiveAt) >= holdFor:
				i.Firing, i.FiredAt, i.Flagged = true, ts, in.flagged
				emit(TransitionFiring, i, in.flagged)
			case i.Firing && ts.Sub(i.ActiveAt) < holdFor:
				emit(TransitionResolved, i, false)
				i.Firing, i.FiredAt, i.Flagged = false, time.Time{}, false
			case changed:
				i.Flagged = in.flagged
				emit(TransitionUpdate, i, in.flagged)
			}
			continue
		}
		if in.incompleteRest || in.incomplete[k] {
			if i.Firing && !i.Stale {
				i.Stale = true
				emit(TransitionStale, i, true)
			}
			continue
		}
		if !i.Firing {
			delete(a.active, k)
			continue
		}
		keep := false
		if keepFor > 0 {
			if i.KeepFiringSince.IsZero() {
				i.KeepFiringSince = ts
			}
			keep = ts.Sub(i.KeepFiringSince) < keepFor
		}
		i.LastEval = ts
		if !keep {
			emit(TransitionResolved, i, false)
			delete(a.active, k)
			continue
		}
		if ts.Sub(i.ActiveAt) < holdFor {
			emit(TransitionResolved, i, false)
			i.Firing, i.FiredAt, i.KeepFiringSince, i.Flagged = false, time.Time{}, time.Time{}, false
		}
	}
	return out, nil
}

// staleAll marks every firing instance stale, used when a rule cannot be evaluated.
func (a *alertSet) staleAll() []transition {
	var out []transition
	for _, k := range a.sortedKeys() {
		i := a.active[k]
		if i.Firing && !i.Stale {
			i.Stale = true
			out = append(out, transition{kind: TransitionStale, inst: *i, incomplete: true})
		}
	}
	return out
}

// restore keeps firing instances and shifts pending ones past the outage, dropping them beyond tolerance.
func (a *alertSet) restore(insts []*instance, downtime, tolerance time.Duration) (resumed bool) {
	resumed = downtime <= tolerance
	for _, i := range insts {
		if !i.Firing {
			if !resumed {
				continue
			}
			i.ActiveAt = i.ActiveAt.Add(downtime)
		}
		a.active[i.Key] = i
	}
	return resumed
}

// jsonFloat persists NaN and infinities, which encoding/json rejects as numbers.
type jsonFloat float64

func (f jsonFloat) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatFloat(float64(f), 'g', -1, 64))
}

func (f *jsonFloat) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := strconv.ParseFloat(s, 64)
	*f = jsonFloat(v)
	return err
}

var (
	tmplLabelRe = regexp.MustCompile(`\{\{-?\s*(?:\$labels|\.Labels)\.([A-Za-z_][A-Za-z0-9_]*)\s*-?\}\}`)
	tmplValueRe = regexp.MustCompile(`\{\{-?\s*(?:\$value|\.Value)\s*-?\}\}`)
)

// expand substitutes {{ $labels.x }} and {{ $value }} in a Prometheus annotation template.
func expand(text string, lbls map[string]string, v float64) string {
	if text == "" {
		return ""
	}
	text = tmplLabelRe.ReplaceAllStringFunc(text, func(m string) string {
		return lbls[tmplLabelRe.FindStringSubmatch(m)[1]]
	})
	return tmplValueRe.ReplaceAllLiteralString(text, strconv.FormatFloat(v, 'g', -1, 64))
}
