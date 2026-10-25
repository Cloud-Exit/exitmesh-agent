package imagesbom

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	scalibrlog "github.com/google/osv-scalibr/log"
)

// scalibr logs through a process-wide logger; route it to the agent's redacting handler at debug level.
var (
	scalibrSink atomic.Pointer[slog.Logger]
	scalibrOnce sync.Once
)

func routeScalibrLogs(l *slog.Logger) {
	scalibrSink.Store(l.With("component", "imagesbom"))
	scalibrOnce.Do(func() { scalibrlog.SetLogger(scalibrLogger{}) })
}

type scalibrLogger struct{}

func (scalibrLogger) logf(format string, args ...any) {
	if l := scalibrSink.Load(); l != nil {
		l.Debug("scalibr: " + fmt.Sprintf(format, args...))
	}
}

func (s scalibrLogger) log(args ...any) { s.logf("%s", fmt.Sprint(args...)) }

func (s scalibrLogger) Errorf(format string, args ...any) { s.logf(format, args...) }
func (s scalibrLogger) Warnf(format string, args ...any)  { s.logf(format, args...) }
func (s scalibrLogger) Infof(format string, args ...any)  { s.logf(format, args...) }
func (s scalibrLogger) Debugf(format string, args ...any) { s.logf(format, args...) }
func (s scalibrLogger) Error(args ...any)                 { s.log(args...) }
func (s scalibrLogger) Warn(args ...any)                  { s.log(args...) }
func (s scalibrLogger) Info(args ...any)                  { s.log(args...) }
func (s scalibrLogger) Debug(args ...any)                 { s.log(args...) }
