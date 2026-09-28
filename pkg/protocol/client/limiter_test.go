package client

import (
	"context"
	"testing"
	"time"
)

type stepClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *stepClock) Now() time.Time { return c.now }

func (c *stepClock) After(d time.Duration) <-chan time.Time {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

func TestLimiterChargesBeforeSending(t *testing.T) {
	clk := &stepClock{now: time.Unix(0, 0)}
	l := limiter{rate: 1000}
	for i := 0; i < 3; i++ {
		if err := l.wait(context.Background(), clk, 500); err != nil {
			t.Fatal(err)
		}
	}
	if len(clk.sleeps) != 3 || clk.now.Sub(time.Unix(0, 0)) != 1500*time.Millisecond {
		t.Fatalf("sleeps %v", clk.sleeps)
	}
	clk.now = clk.now.Add(10 * time.Second)
	if err := l.wait(context.Background(), clk, 100); err != nil || clk.sleeps[3] != 100*time.Millisecond {
		t.Fatalf("idle limiter accumulated credit: %v", clk.sleeps)
	}
	off := limiter{}
	if err := off.wait(context.Background(), clk, 1<<30); err != nil || len(clk.sleeps) != 4 {
		t.Fatal("unlimited limiter waited")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	blocked := limiter{rate: 1}
	if err := blocked.wait(ctx, realClock{}, 10); err == nil {
		t.Fatal("canceled wait returned nil")
	}
}
