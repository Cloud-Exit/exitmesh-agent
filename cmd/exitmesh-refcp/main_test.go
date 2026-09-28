package main

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

func TestServesEnrollmentAndTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-create-cluster", "-create-host=2", "-cert-dir", t.TempDir()}, pw, io.Discard)
		pw.Close()
	}()
	lines := map[string][]string{}
	sc := bufio.NewScanner(pr)
	for len(lines["target"]) < 3 && sc.Scan() {
		f := strings.Fields(sc.Text())
		lines[f[0]] = append(lines[f[0]], strings.Join(f[1:], " "))
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	if len(lines["ca"]) != 1 || len(lines["endpoint"]) != 1 || len(lines["target"]) != 3 {
		t.Fatalf("output %v", lines)
	}
	var clusterTok string
	hosts := 0
	for _, l := range lines["target"] {
		f := strings.Fields(l)
		switch f[0] {
		case protocol.TargetKubernetes:
			clusterTok = f[3]
		case protocol.TargetHost:
			hosts++
		}
		tok, err := protocol.ParseEnrollmentToken(f[3])
		if id, _ := tok.TargetID(); err != nil || id != f[1] {
			t.Fatalf("token %q: %v", f[3], err)
		}
	}
	if clusterTok == "" || hosts != 2 {
		t.Fatalf("targets %v", lines["target"])
	}
	opts := tunnel.Options{Endpoint: lines["endpoint"][0], CAFile: lines["ca"][0]}
	wid, _ := protocol.NewWriterID()
	res, err := tunnel.Enroll(ctx, opts, protocol.EnrollRequest{Token: clusterTok, WriterID: wid, TargetType: protocol.TargetKubernetes})
	if err != nil {
		t.Fatal(err)
	}
	opts.Credential = func() string { return res.Credential }
	tr, err := tunnel.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tr.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Handle(func(context.Context, *client.Request) (any, error) { return nil, nil })
	ep, _ := protocol.NewEpoch(time.Now())
	var hr protocol.HelloResult
	err = c.Call(ctx, protocol.MethodHello, protocol.HelloParams{
		TargetID: res.TargetID, WriterID: wid, Incarnation: 1, Epoch: ep,
		EpochOpen: &protocol.EpochOpen{Reason: protocol.OpenInitial}, Agent: protocol.AgentInfo{Protocol: 1},
	}, &hr)
	if err != nil || hr.Decision != protocol.DecisionOpened {
		t.Fatalf("hello %+v %v", hr, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestFlagsAndNames(t *testing.T) {
	if err := run(context.Background(), []string{"-nope"}, io.Discard, io.Discard); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := run(context.Background(), []string{"-create-host=x"}, io.Discard, io.Discard); err == nil {
		t.Fatal("bad count accepted")
	}
	var c countFlag
	for _, v := range []string{"true", "true"} {
		_ = c.Set(v)
	}
	if c.String() != "2" {
		t.Fatalf("repeated flag counted %s", c.String())
	}
	if err := run(context.Background(), []string{"extra"}, io.Discard, io.Discard); err == nil {
		t.Fatal("positional argument accepted")
	}
	if err := run(context.Background(), []string{"-listen", "256.0.0.1:1"}, io.Discard, io.Discard); err == nil {
		t.Fatal("bad listen address accepted")
	}
	names := certNames("0.0.0.0:8443", "cp.dev, 10.0.0.5")
	if len(names) != 6 || names[4] != "cp.dev" || names[5] != "10.0.0.5" {
		t.Fatalf("names %v", names)
	}
	if names := certNames("192.168.1.2:8443", ""); names[3] != "192.168.1.2" {
		t.Fatalf("names %v", names)
	}
}
