package protocol

import (
	"encoding/json"
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
