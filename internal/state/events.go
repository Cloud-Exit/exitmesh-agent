package state

import (
	"regexp"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	eventBuckets    = 60
	maxEventReasons = 16
	otherReason     = "_other"
)

type evBucket struct {
	start int64
	n     int64
}

type seenEvent struct {
	count int64
	last  time.Time
	ns    string
}

type objEvents struct {
	ns        string
	reasons   map[string][]evBucket
	published map[string]int64
	lastEmit  time.Time
	emitted   bool
	dirty     bool
}

// eventAgg counts Warning event occurrences per involved object and reason in a sliding window.
type eventAgg struct {
	window, interval, bucket time.Duration
	objs                     map[string]*objEvents
	seen                     map[string]*seenEvent
}

func newEventAgg(window, interval time.Duration) *eventAgg {
	b := window / eventBuckets
	if b <= 0 {
		b = window
	}
	return &eventAgg{window: window, interval: interval, bucket: b, objs: map[string]*objEvents{}, seen: map[string]*seenEvent{}}
}

var reasonSanitize = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func sanitizeReason(r string) string {
	r = reasonSanitize.ReplaceAllString(r, "_")
	if len(r) > 64 {
		r = r[:64]
	}
	if r == "" {
		return "Unknown"
	}
	return r
}

func nestedTime(obj map[string]any, fields ...string) time.Time {
	s, ok, _ := unstructured.NestedString(obj, fields...)
	if !ok || s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func nestedInt(obj map[string]any, fields ...string) int64 {
	v, ok, _ := unstructured.NestedFieldNoCopy(obj, fields...)
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// observe records the new occurrences carried by a Warning event and returns the involved object UID.
func (a *eventAgg) observe(ev *unstructured.Unstructured, now time.Time) (string, bool) {
	o := ev.Object
	typ, _, _ := unstructured.NestedString(o, "type")
	if typ != "Warning" {
		return "", false
	}
	involved, _, _ := unstructured.NestedString(o, "involvedObject", "uid")
	if involved == "" {
		involved, _, _ = unstructured.NestedString(o, "regarding", "uid")
	}
	if involved == "" {
		return "", false
	}
	reason, _, _ := unstructured.NestedString(o, "reason")
	reason = sanitizeReason(reason)
	count := max(nestedInt(o, "count"), nestedInt(o, "deprecatedCount"), nestedInt(o, "series", "count"), 1)
	last := firstTime(nestedTime(o, "series", "lastObservedTime"), nestedTime(o, "lastTimestamp"),
		nestedTime(o, "deprecatedLastTimestamp"), nestedTime(o, "eventTime"), now)
	if last.After(now) {
		last = now
	}
	first := firstTime(nestedTime(o, "firstTimestamp"), nestedTime(o, "deprecatedFirstTimestamp"), nestedTime(o, "eventTime"), last)
	evUID := string(ev.GetUID())
	start := now.Add(-a.window)
	prev := a.seen[evUID]
	var delta int64
	switch {
	case prev != nil:
		delta = count - prev.count
	case !first.Before(start):
		delta = count
	case last.Before(start):
		delta = 0
	default:
		span := last.Sub(first)
		delta = max(1, int64(float64(count)*float64(last.Sub(start))/float64(span)))
	}
	if evUID != "" {
		a.seen[evUID] = &seenEvent{count: count, last: last, ns: ev.GetNamespace()}
	}
	if delta <= 0 || last.Before(start) {
		return "", false
	}
	ob := a.objs[involved]
	if ob == nil {
		ob = &objEvents{ns: ev.GetNamespace(), reasons: map[string][]evBucket{}}
		a.objs[involved] = ob
	}
	bs := last.Truncate(a.bucket).UnixMilli()
	list := ob.reasons[reason]
	if n := len(list); n > 0 && list[n-1].start == bs {
		list[n-1].n += delta
	} else {
		list = append(list, evBucket{start: bs, n: delta})
		sort.Slice(list, func(i, j int) bool { return list[i].start < list[j].start })
		merged := list[:1]
		for _, b := range list[1:] {
			if b.start == merged[len(merged)-1].start {
				merged[len(merged)-1].n += b.n
			} else {
				merged = append(merged, b)
			}
		}
		list = merged
	}
	ob.reasons[reason] = list
	ob.dirty = true
	return involved, true
}

// counts prunes expired buckets and returns the capped occurrence counts per reason.
func (a *eventAgg) counts(ob *objEvents, now time.Time) map[string]int64 {
	cut := now.Add(-a.window).UnixMilli()
	type rc struct {
		reason string
		n      int64
	}
	var all []rc
	for r, list := range ob.reasons {
		i := 0
		for i < len(list) && list[i].start < cut {
			i++
		}
		list = list[i:]
		if len(list) == 0 {
			delete(ob.reasons, r)
			continue
		}
		ob.reasons[r] = list
		var n int64
		for _, b := range list {
			n += b.n
		}
		all = append(all, rc{r, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].reason < all[j].reason
	})
	out := map[string]int64{}
	for i, c := range all {
		if i < maxEventReasons {
			out[c.reason] = c.n
		} else {
			out[otherReason] += c.n
		}
	}
	return out
}

func (a *eventAgg) publishCounts(uid string, now time.Time) {
	ob := a.objs[uid]
	if ob == nil {
		return
	}
	ob.published = a.counts(ob, now)
	ob.lastEmit = now
	ob.emitted = true
	ob.dirty = false
}

func (a *eventAgg) fields(uid string) map[string]any {
	ob := a.objs[uid]
	if ob == nil || len(ob.published) == 0 {
		return nil
	}
	out := make(map[string]any, len(ob.published))
	for r, n := range ob.published {
		out[eventFieldPrefix+r] = n
	}
	return out
}

func (a *eventAgg) dueNow(uid string, now time.Time) bool {
	ob := a.objs[uid]
	return ob != nil && (!ob.emitted || now.Sub(ob.lastEmit) >= a.interval)
}

// due returns the objects whose counts may have changed and whose last update is at least one interval old.
func (a *eventAgg) due(now time.Time) []string {
	var out []string
	for uid, ob := range a.objs {
		if (ob.dirty || len(ob.published) > 0) && a.dueNow(uid, now) {
			out = append(out, uid)
		}
	}
	sort.Strings(out)
	return out
}

func (a *eventAgg) prune(now time.Time) {
	cut := now.Add(-a.window)
	for uid, ob := range a.objs {
		a.counts(ob, now)
		if len(ob.reasons) == 0 && len(ob.published) == 0 {
			delete(a.objs, uid)
		}
	}
	for id, s := range a.seen {
		if s.last.Before(cut) {
			delete(a.seen, id)
		}
	}
}

func (a *eventAgg) forget(uid string) { delete(a.objs, uid) }

func (a *eventAgg) forgetEvent(evUID string) { delete(a.seen, evUID) }

func (a *eventAgg) retainEvents(namespace string, keep map[string]bool) {
	for id, s := range a.seen {
		if (namespace == "" || s.ns == namespace) && !keep[id] {
			delete(a.seen, id)
		}
	}
}

// dropScope clears aggregation for a namespace (all when empty), republishing each object without counts.
func (a *eventAgg) dropScope(namespace string, republish func(uid string)) {
	for id, s := range a.seen {
		if namespace == "" || s.ns == namespace {
			delete(a.seen, id)
		}
	}
	var uids []string
	for uid, ob := range a.objs {
		if namespace == "" || ob.ns == namespace {
			ob.reasons = map[string][]evBucket{}
			uids = append(uids, uid)
		}
	}
	sort.Strings(uids)
	for _, uid := range uids {
		republish(uid)
		delete(a.objs, uid)
	}
}
