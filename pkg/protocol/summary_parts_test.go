package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSplitSummaryKeepsEveryEntryInBoundedParts(t *testing.T) {
	sum := SummaryParams{Epoch: EpochID{1}, Watermark: 90, Head: 40}
	for i := 0; i < 500; i++ {
		sum.Entries = append(sum.Entries, SummaryEntry{
			FindingID: fmt.Sprintf("f%04d", i), DedupKey: strings.Repeat("k", 100), State: LifecycleFiring, Severity: "high",
		})
	}
	parts, err := SplitSummary(sum, 8<<10)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("parts %d", len(parts))
	}
	var joined []SummaryEntry
	for i, p := range parts {
		if p.Part != uint32(i) || p.More != (i < len(parts)-1) || p.Epoch != sum.Epoch || p.Watermark != 90 || p.Head != 40 {
			t.Fatalf("part %d header %+v", i, p)
		}
		b, _ := json.Marshal(p.Entries)
		if len(b) > 8<<10 {
			t.Fatalf("part %d holds %d bytes", i, len(b))
		}
		joined = append(joined, p.Entries...)
	}
	if !reflect.DeepEqual(joined, sum.Entries) {
		t.Fatal("parts do not join to the summary")
	}
}

func TestSplitSummaryOfNothingIsOneEmptyPart(t *testing.T) {
	parts, err := SplitSummary(SummaryParams{Watermark: 5, Head: 4}, SummaryPartBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0].More || parts[0].Part != 0 || parts[0].Entries == nil || len(parts[0].Entries) != 0 {
		t.Fatalf("parts %+v", parts)
	}
	b, _ := json.Marshal(parts[0])
	if strings.Contains(string(b), "part") || strings.Contains(string(b), "more") {
		t.Fatalf("a whole summary carries part fields: %s", b)
	}
}

// JSON escaping can make one entry far larger than its finding; such an entry fits no part and is refused.
func TestSplitSummaryRefusesAnEntryLargerThanAPart(t *testing.T) {
	sum := SummaryParams{Watermark: 9, Head: 8, Entries: []SummaryEntry{
		{FindingID: "small", DedupKey: "k", State: LifecycleFiring},
		{FindingID: "huge", DedupKey: strings.Repeat("<", 3000), State: LifecycleFiring},
	}}
	_, err := SplitSummary(sum, 8<<10)
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "huge") {
		t.Fatalf("err %v", err)
	}
}

func TestSplitSummaryRefusesALoneOversizedEntry(t *testing.T) {
	sum := SummaryParams{Watermark: 3, Head: 1, Entries: []SummaryEntry{{FindingID: "only", DedupKey: strings.Repeat("k", 9000), State: LifecycleFiring}}}
	parts, err := SplitSummary(sum, 8<<10)
	if !errors.Is(err, ErrTooLarge) || parts != nil {
		t.Fatalf("parts %d err %v", len(parts), err)
	}
}

// A valid finding of about 3 MiB escapes to an entry over the largest frame, so no part limit can carry it.
func TestSplitSummaryRefusesAValidFindingThatEscapesPastTheFrameLimit(t *testing.T) {
	key := strings.Repeat("<", 3<<19)
	b := newChainBuilder(t)
	f := testFinding("big", TransitionFiring, b.now)
	f.DedupKey, f.Provenance.RuleID = key, key
	rec := b.add(&Record{Envelope: b.chain.Next(TypeFinding, 1, b.now), Finding: f})
	if n := len(rec.Bytes()); n > MaxRecordBytes || n < 3<<20 {
		t.Fatalf("finding record is %d bytes", n)
	}
	e := SummaryEntry{FindingID: f.ID, DedupKey: key, State: LifecycleFiring, RuleID: key, Severity: "high"}
	if eb, _ := json.Marshal(e); len(eb) <= MaxFramePayload {
		t.Fatalf("entry is only %d bytes", len(eb))
	}
	sum := SummaryParams{Watermark: 9, Head: 8, Entries: []SummaryEntry{{FindingID: "a", DedupKey: "k", State: LifecycleFiring}, e}}
	parts, err := SplitSummary(sum, SummaryPartBytes)
	if !errors.Is(err, ErrTooLarge) || parts != nil {
		t.Fatalf("parts %d err %v", len(parts), err)
	}
}
