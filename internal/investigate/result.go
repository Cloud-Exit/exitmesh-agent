package investigate

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
)

// Result is the envelope every tool returns (PRD I4).
type Result struct {
	Source      string   `json:"source"`
	Window      Window   `json:"window"`
	Limits      Limits   `json:"limits"`
	Truncated   bool     `json:"truncated"`
	Limitations []string `json:"limitations"`
	QueryHash   string   `json:"query_hash,omitempty"`
	Language    string   `json:"language,omitempty"`
	Query       string   `json:"query,omitempty"`
	Executed    string   `json:"executed_query,omitempty"`
	RetentionMs int64    `json:"retention_ms,omitempty"`
	Data        any      `json:"data"`
}

func (r *Result) limit(format string, a ...any) {
	r.Limitations = append(r.Limitations, fmt.Sprintf(format, a...))
}

// Result types of telemetry data.
const (
	TypeStreams = "streams"
	TypeVector  = "vector"
	TypeMatrix  = "matrix"
	TypeScalar  = "scalar"
)

// Point is a sample encoded as [unix_ms, "value"] so non-finite values survive JSON.
type Point struct {
	T int64
	V float64
}

func (p Point) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{p.T, strconv.FormatFloat(p.V, 'f', -1, 64)})
}

func (p *Point) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
		return fmt.Errorf("point must be [time, value]")
	}
	if err := json.Unmarshal(raw[0], &p.T); err != nil {
		return err
	}
	var s string
	if err := json.Unmarshal(raw[1], &s); err != nil {
		return err
	}
	v, err := strconv.ParseFloat(s, 64)
	p.V = v
	return err
}

// Series is one metric series; Source names the node, coordinator, host, or lookback source.
type Series struct {
	Source string            `json:"source,omitempty"`
	Metric map[string]string `json:"metric"`
	Points []Point           `json:"values"`
}

// LogLine is one log line.
type LogLine struct {
	Source string            `json:"source,omitempty"`
	Time   time.Time         `json:"time"`
	Labels map[string]string `json:"labels"`
	Text   string            `json:"text"`
}

// Telemetry is the data of promql, logql, logsql, and lookback results.
type Telemetry struct {
	ResultType string       `json:"result_type"`
	Series     []Series     `json:"series,omitempty"`
	Lines      []LogLine    `json:"lines,omitempty"`
	Nodes      []NodeStatus `json:"nodes,omitempty"`
}

// NodeStatus reports one fan-out target.
type NodeStatus struct {
	Node        string `json:"node"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	RetentionMs int64  `json:"retention_ms,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// Node fan-out statuses.
const (
	NodeOK        = "ok"
	NodeFailed    = "failed"
	NodeUncovered = "uncovered"
)

func labelMap(ls labels.Labels) map[string]string {
	m := make(map[string]string, ls.Len())
	ls.Range(func(l labels.Label) { m[l.Name] = l.Value })
	return m
}

// fromPromValue converts an engine result, reporting omitted native histograms.
func fromPromValue(v parser.Value) (typ string, series []Series, histograms bool, err error) {
	switch x := v.(type) {
	case promql.Matrix:
		for _, s := range x {
			ps := make([]Point, len(s.Floats))
			for i, f := range s.Floats {
				ps[i] = Point{f.T, f.F}
			}
			histograms = histograms || len(s.Histograms) > 0
			series = append(series, Series{Metric: labelMap(s.Metric), Points: ps})
		}
		return TypeMatrix, series, histograms, nil
	case promql.Vector:
		for _, s := range x {
			if s.H != nil {
				histograms = true
				continue
			}
			series = append(series, Series{Metric: labelMap(s.Metric), Points: []Point{{s.T, s.F}}})
		}
		return TypeVector, series, histograms, nil
	case promql.Scalar:
		return TypeScalar, []Series{{Metric: map[string]string{}, Points: []Point{{x.T, x.V}}}}, false, nil
	}
	return "", nil, false, fmt.Errorf("unsupported result type %s", v.Type())
}

func seriesKey(s Series) string {
	keys := make([]string, 0, len(s.Metric))
	for k := range s.Metric {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	b.WriteString(s.Source)
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte(1)
		b.WriteString(s.Metric[k])
	}
	return b.String()
}

func seriesBytes(s Series) int64 {
	n := int64(len(s.Source) + 16*len(s.Points))
	for k, v := range s.Metric {
		n += int64(len(k) + len(v))
	}
	return n
}

// boundSeries sorts series and applies series, sample, and byte limits.
func boundSeries(in []Series, lim Limits) (out []Series, limited []string) {
	slices.SortFunc(in, func(a, b Series) int { return strings.Compare(seriesKey(a), seriesKey(b)) })
	var samples int
	var size int64
	for i, s := range in {
		switch {
		case i >= lim.MaxSeries:
			return out, append(limited, fmt.Sprintf("series limit %d reached; %d series omitted", lim.MaxSeries, len(in)-i))
		case samples+len(s.Points) > lim.MaxSamples:
			return out, append(limited, fmt.Sprintf("sample limit %d reached; %d series omitted", lim.MaxSamples, len(in)-i))
		case size+seriesBytes(s) > lim.MaxBytes:
			return out, append(limited, fmt.Sprintf("byte limit %d reached; %d series omitted", lim.MaxBytes, len(in)-i))
		}
		samples += len(s.Points)
		size += seriesBytes(s)
		out = append(out, s)
	}
	return out, nil
}

// boundLines orders lines by direction and applies line and byte limits.
func boundLines(in []LogLine, lim Limits, forward bool) (out []LogLine, limited []string) {
	slices.SortStableFunc(in, func(a, b LogLine) int {
		if forward {
			return a.Time.Compare(b.Time)
		}
		return b.Time.Compare(a.Time)
	})
	var size int64
	for i, l := range in {
		switch {
		case i >= lim.MaxLines:
			return out, append(limited, fmt.Sprintf("line limit %d reached; %d lines omitted", lim.MaxLines, len(in)-i))
		case size+int64(len(l.Text)) > lim.MaxBytes:
			return out, append(limited, fmt.Sprintf("byte limit %d reached; %d lines omitted", lim.MaxBytes, len(in)-i))
		}
		size += int64(len(l.Text))
		out = append(out, l)
	}
	return out, nil
}
