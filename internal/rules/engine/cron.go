package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cronSchedule is a parsed standard five-field schedule, as Kubernetes CronJobs accept it.
type cronSchedule struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
	every                         time.Duration
	loc                           *time.Location
}

type cronField struct {
	min, max int
	names    map[string]int
	// sunday7 accepts 7 as a second spelling of Sunday.
	sunday7 bool
}

var (
	cronMinute = cronField{min: 0, max: 59}
	cronHour   = cronField{min: 0, max: 23}
	cronDom    = cronField{min: 1, max: 31}
	cronMonth  = cronField{min: 1, max: 12, names: map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}}
	cronDow = cronField{min: 0, max: 6, sunday7: true, names: map[string]int{
		"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
	}}
)

var cronDescriptors = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

// cronSearchLimit bounds the backward search; a schedule matching nothing within it (such as February 30) fails.
const cronSearchLimit = 5 * 366 * 24 * time.Hour

func parseCron(spec, timeZone string) (*cronSchedule, error) {
	spec = strings.TrimSpace(spec)
	if rest, ok := cutTZ(spec); ok {
		zone, after, _ := strings.Cut(rest, " ")
		if timeZone == "" {
			timeZone = zone
		}
		spec = strings.TrimSpace(after)
	}
	loc := time.UTC
	if timeZone != "" {
		l, err := time.LoadLocation(timeZone)
		if err != nil {
			return nil, fmt.Errorf("cron: time zone %q: %w", timeZone, err)
		}
		loc = l
	}
	if d, ok := strings.CutPrefix(spec, "@every "); ok {
		every, err := time.ParseDuration(strings.TrimSpace(d))
		if err != nil || every < time.Second {
			return nil, fmt.Errorf("cron: invalid @every interval %q", d)
		}
		return &cronSchedule{every: every, loc: loc}, nil
	}
	if expanded, ok := cronDescriptors[strings.ToLower(spec)]; ok {
		spec = expanded
	}
	parts := strings.Fields(spec)
	if len(parts) != 5 {
		return nil, fmt.Errorf("cron: %q has %d fields, want 5", spec, len(parts))
	}
	s := &cronSchedule{loc: loc}
	var err error
	if s.minute, _, err = cronParseField(parts[0], cronMinute); err != nil {
		return nil, err
	}
	if s.hour, _, err = cronParseField(parts[1], cronHour); err != nil {
		return nil, err
	}
	if s.dom, s.domStar, err = cronParseField(parts[2], cronDom); err != nil {
		return nil, err
	}
	if s.month, _, err = cronParseField(parts[3], cronMonth); err != nil {
		return nil, err
	}
	if s.dow, s.dowStar, err = cronParseField(parts[4], cronDow); err != nil {
		return nil, err
	}
	return s, nil
}

func cutTZ(spec string) (string, bool) {
	for _, p := range []string{"CRON_TZ=", "TZ="} {
		if rest, ok := strings.CutPrefix(spec, p); ok {
			return rest, true
		}
	}
	return "", false
}

func cronParseField(text string, f cronField) (uint64, bool, error) {
	var bits uint64
	star := false
	for _, part := range strings.Split(text, ",") {
		rangePart, stepPart, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepPart)
			if err != nil || n < 1 {
				return 0, false, fmt.Errorf("cron: invalid step in %q", part)
			}
			step = n
		}
		lo, hi := f.min, f.max
		switch rangePart {
		case "*", "?":
			star = star || !hasStep
		default:
			a, b, isRange := strings.Cut(rangePart, "-")
			var err error
			if lo, err = cronValue(a, f); err != nil {
				return 0, false, err
			}
			hi = lo
			if isRange {
				if hi, err = cronValue(b, f); err != nil {
					return 0, false, err
				}
			} else if hasStep {
				hi = f.max
			}
		}
		if lo > hi {
			return 0, false, fmt.Errorf("cron: range %q is reversed", rangePart)
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v%(f.max+1))
		}
	}
	if bits == 0 {
		return 0, false, errors.New("cron: empty field " + strconv.Quote(text))
	}
	return bits, star, nil
}

func cronValue(text string, f cronField) (int, error) {
	if n, ok := f.names[strings.ToLower(text)]; ok {
		return n, nil
	}
	n, err := strconv.Atoi(text)
	maxValue := f.max
	if f.sunday7 {
		maxValue++
	}
	if err != nil || n < f.min || n > maxValue {
		return 0, fmt.Errorf("cron: value %q is outside %d-%d", text, f.min, maxValue)
	}
	return n, nil
}

func (s *cronSchedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	if s.domStar || s.dowStar {
		return dom && dow
	}
	return dom || dow
}

// previous returns the latest scheduled time at or before at.
func (s *cronSchedule) previous(at time.Time) (time.Time, error) {
	if s.every > 0 {
		return at.Truncate(s.every), nil
	}
	at = at.In(s.loc)
	t := time.Date(at.Year(), at.Month(), at.Day(), at.Hour(), at.Minute(), 0, 0, s.loc)
	limit := at.Add(-cronSearchLimit)
	for !t.Before(limit) {
		switch {
		case s.month&(1<<uint(t.Month())) == 0:
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, s.loc).Add(-time.Minute)
		case !s.dayMatches(t):
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, s.loc).Add(-time.Minute)
		case s.hour&(1<<uint(t.Hour())) == 0:
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, s.loc).Add(-time.Minute)
		case s.minute&(1<<uint(t.Minute())) == 0:
			t = t.Add(-time.Minute)
		default:
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cron: no scheduled time within %s before %s", cronSearchLimit, at.UTC().Format(time.RFC3339))
}

// cronPreviousMillis is the CEL binding: the latest scheduled time at or before atMillis, in Unix milliseconds.
func cronPreviousMillis(schedule, timeZone string, atMillis int64) (int64, error) {
	s, err := parseCron(schedule, timeZone)
	if err != nil {
		return 0, err
	}
	t, err := s.previous(time.UnixMilli(atMillis))
	if err != nil {
		return 0, err
	}
	return t.UnixMilli(), nil
}
