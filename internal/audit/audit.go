// Package audit writes an append-only JSONL record of every decision and every
// network request the framework makes, so a run is fully reconstructable.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`    // "request" | "decision" | "finding" | "refusal" | "note"
	Target  string    `json:"target,omitempty"`
	Method  string    `json:"method,omitempty"`
	URL     string    `json:"url,omitempty"`
	Status  int       `json:"status,omitempty"`
	Message string    `json:"message,omitempty"`
}

type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	f   *os.File
	tee io.Writer
}

// New opens (or creates) an audit log file. If path is empty, logs only to tee.
func New(path string, tee io.Writer) (*Logger, error) {
	l := &Logger{tee: tee}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		l.f = f
		l.w = f
	}
	return l, nil
}

func (l *Logger) Log(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(e)
	if l.w != nil {
		l.w.Write(b)
		l.w.Write([]byte("\n"))
	}
	if l.tee != nil {
		l.tee.Write(b)
		l.tee.Write([]byte("\n"))
	}
}

func (l *Logger) Close() {
	if l.f != nil {
		l.f.Close()
	}
}
