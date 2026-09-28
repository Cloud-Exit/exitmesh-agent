package evidence

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func sample(i int, text string) Sample {
	return Sample{Time: time.Unix(int64(i), 0), Text: text}
}

func size(text string) int64 { return int64(len(text) + sampleOverhead) }

func TestSharesEvictionAndLimited(t *testing.T) {
	r := New(1000)
	r.SetRules(map[string]float64{"a": 1, "b": 1, "c": 2})
	st := r.Stats()
	if st.Rules["a"].Share != 250 || st.Rules["b"].Share != 250 || st.Rules["c"].Share != 500 {
		t.Fatalf("shares %+v", st.Rules)
	}
	text := strings.Repeat("x", 36)
	for i := 0; i < 5; i++ {
		if !r.Add("a", sample(i, text)) {
			t.Fatal("rejected")
		}
	}
	st = r.Stats()
	if got := st.Rules["a"]; got.Samples != 2 || got.Evicted != 3 || !got.Limited || got.Bytes != 2*size(text) {
		t.Fatalf("rule a %+v", got)
	}
	if r.Limited("b") || !r.Limited("a") || fmt.Sprint(r.LimitedRules()) != "[a]" {
		t.Fatal("limited flags")
	}
	got, limited := r.Take("a", 10)
	if !limited || len(got) != 2 || got[0].Time.Unix() != 3 || got[1].Time.Unix() != 4 {
		t.Fatalf("take %+v %v", got, limited)
	}
	if r.Add("a", sample(9, text)); !r.Limited("a") {
		t.Fatal("limited must stay sticky while active")
	}
	if got, limited := r.Take("a", 10); limited || len(got) != 1 {
		t.Fatalf("second take %+v %v", got, limited)
	}
	if r.Stats().Bytes != 0 {
		t.Fatalf("bytes after take %d", r.Stats().Bytes)
	}
}

func TestTakeNewestAndRejectOversize(t *testing.T) {
	r := New(10_000)
	for i := 0; i < 5; i++ {
		r.Add("r", sample(i, "line"))
	}
	got, limited := r.Take("r", 2)
	if limited || len(got) != 2 || got[0].Time.Unix() != 3 || got[1].Time.Unix() != 4 {
		t.Fatalf("take %+v", got)
	}
	if got, _ := r.Take("r", 2); len(got) != 0 {
		t.Fatal("take must clear")
	}
	if got, _ := r.Take("unknown", 2); got != nil {
		t.Fatal("unknown rule")
	}
	if r.Add("r", sample(0, strings.Repeat("y", 20_000))) {
		t.Fatal("oversized sample kept")
	}
	if st := r.Stats().Rules["r"]; st.Rejected != 1 || !st.Limited {
		t.Fatalf("stats %+v", st)
	}
}

func TestSetRulesReshareAndDrop(t *testing.T) {
	r := New(1000)
	text := strings.Repeat("z", 36)
	r.SetRules(map[string]float64{"a": 1})
	for i := 0; i < 10; i++ {
		r.Add("a", sample(i, text))
	}
	if st := r.Stats().Rules["a"]; st.Samples != 10 || st.Limited {
		t.Fatalf("single rule %+v", st)
	}
	r.SetRules(map[string]float64{"a": 1, "b": 0})
	st := r.Stats()
	if st.Rules["a"].Share != 500 || st.Rules["b"].Weight != 1 || st.Rules["a"].Samples != 5 || !st.Rules["a"].Limited || st.Bytes != 5*size(text) {
		t.Fatalf("reshare %+v", st)
	}
	r.Add("c", sample(1, text))
	if st := r.Stats(); st.Rules["c"].Share != 333 || st.Rules["a"].Share != 333 {
		t.Fatalf("implicit activation %+v", st.Rules)
	}
	r.SetRules(map[string]float64{"b": 1})
	st = r.Stats()
	if len(st.Rules) != 1 || st.Bytes != 0 || st.Rules["b"].Share != 1000 {
		t.Fatalf("drop %+v", st)
	}
}

func TestDefensiveRedaction(t *testing.T) {
	r := New(0)
	if r.Stats().Ceiling != DefaultCeiling {
		t.Fatal("default ceiling")
	}
	r.Add("r", Sample{Text: "login failed password=hunter2 for bob", Labels: map[string]string{"token": "abc", "pod": "api"}})
	got, _ := r.Take("r", 1)
	if strings.Contains(got[0].Text, "hunter2") || got[0].Labels["token"] == "abc" || got[0].Labels["pod"] != "api" {
		t.Fatalf("not redacted %+v", got[0])
	}
}

func TestCeilingHoldsUnderConcurrentFlood(t *testing.T) {
	r := New(64 << 10)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 600; i++ {
				r.Add(fmt.Sprintf("rule-%d", (g+i)%13), sample(i, strings.Repeat("m", i%300)))
				if i%150 == 0 {
					r.Take(fmt.Sprintf("rule-%d", g), 5)
				}
			}
		}(g)
	}
	wg.Wait()
	st := r.Stats()
	var sum, shares int64
	for _, rs := range st.Rules {
		sum += rs.Bytes
		shares += rs.Share
		if rs.Bytes > rs.Share {
			t.Fatalf("share exceeded %+v", rs)
		}
	}
	if sum != st.Bytes || st.Bytes > st.Ceiling || shares > st.Ceiling {
		t.Fatalf("bytes %d sum %d shares %d ceiling %d", st.Bytes, sum, shares, st.Ceiling)
	}
}
