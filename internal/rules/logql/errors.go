// Package logql implements the LogQL subset published in docs/logql-subset.md without Loki code.
package logql

import "fmt"

// SubsetDoc is the published reference for the supported grammar.
const SubsetDoc = "docs/logql-subset.md"

// ParseError reports malformed input at a byte offset.
type ParseError struct {
	Pos int
	Msg string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("logql: parse error at position %d: %s", e.Pos, e.Msg)
}

// UnsupportedError reports a valid LogQL construct outside the published subset.
type UnsupportedError struct {
	Pos       int
	Construct string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("logql: unsupported construct %s at position %d; see %s for the supported subset", e.Construct, e.Pos, SubsetDoc)
}

// BudgetError reports a rule whose counters cannot fit its memory budget.
type BudgetError struct {
	Buckets      int
	MaxSeries    int
	Required     int
	CounterBytes int
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("logql: rule counters need %d bytes (%d buckets x %d series x %d bytes) but the counter budget is %d bytes",
		e.Required, e.Buckets, e.MaxSeries, bucketBytes, e.CounterBytes)
}

// TranslationError reports a LogQL construct without an exact LogsQL mapping.
type TranslationError struct {
	Construct string
	Reason    string
}

func (e *TranslationError) Error() string {
	return fmt.Sprintf("logql: cannot translate %s to LogsQL: %s", e.Construct, e.Reason)
}

// PipelineError reports samples carrying __error__ in a metric evaluation, as Loki does.
type PipelineError struct {
	Err string
}

func (e *PipelineError) Error() string {
	return fmt.Sprintf("logql: pipeline error %q in metric evaluation; add | __error__=\"\" to skip lines that fail parsing", e.Err)
}
