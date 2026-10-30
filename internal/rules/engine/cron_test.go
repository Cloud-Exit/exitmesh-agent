package engine

import (
	"testing"
	"time"
)

func TestCronPrevious(t *testing.T) {
	at := time.Date(2026, 10, 21, 15, 7, 30, 0, time.UTC)
	cases := []struct {
		spec, zone string
		want       time.Time
	}{
		{"*/5 * * * *", "", time.Date(2026, 10, 21, 15, 5, 0, 0, time.UTC)},
		{"0 2 * * *", "", time.Date(2026, 10, 21, 2, 0, 0, 0, time.UTC)},
		{"0 16 * * *", "", time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC)},
		{"@hourly", "", time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC)},
		{"@daily", "", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)},
		{"@weekly", "", time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)},
		{"@monthly", "", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		{"@yearly", "", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"30 9 * * mon-fri", "", time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC)},
		{"0 0 * * 7", "", time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)},
		{"0 0 1,15 FEB *", "", time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)},
		{"0 0 13 * 5", "", time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)},
		{"7 15 21 10 *", "", time.Date(2026, 10, 21, 15, 7, 0, 0, time.UTC)},
		{"0 2 * * *", "Europe/Amsterdam", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)},
		{"CRON_TZ=Asia/Kolkata 0 * * * *", "", time.Date(2026, 10, 21, 14, 30, 0, 0, time.UTC)},
		{"@every 1h", "", time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		got, err := cronPreviousMillis(c.spec, c.zone, at.UnixMilli())
		if err != nil {
			t.Fatalf("%q: %v", c.spec, err)
		}
		if !time.UnixMilli(got).Equal(c.want) {
			t.Errorf("%q in %q: previous %s, want %s", c.spec, c.zone, time.UnixMilli(got).UTC(), c.want)
		}
	}
}

func TestCronPreviousRejectsInvalidSchedules(t *testing.T) {
	at := time.Date(2026, 10, 21, 15, 7, 0, 0, time.UTC).UnixMilli()
	for _, spec := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "0 0 30 2 *", "5-1 * * * *", "*/0 * * * *", "@every 0s", "0 0 * * 8"} {
		if _, err := cronPreviousMillis(spec, "", at); err == nil {
			t.Errorf("%q: no error", spec)
		}
	}
	if _, err := cronPreviousMillis("0 0 * * *", "Mars/Olympus", at); err == nil {
		t.Error("unknown time zone: no error")
	}
}
