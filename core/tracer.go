package core

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Span struct {
	name      string
	startTime time.Time
	parent    *Span
	depth     int
}

var (
	mu sync.Mutex
)

// StartSpan starts a new span with the given name and optional parent span
func StartSpan(name string, parent *Span, message ...string) *Span {
	mu.Lock()
	defer mu.Unlock()

	depth := 0
	if parent != nil {
		depth = parent.depth + 1
	}

	span := &Span{
		name:      name,
		startTime: time.Now(),
		parent:    parent,
		depth:     depth,
	}

	// Print start message for root spans
	if len(message) > 0 {
		fmt.Printf("%s\n", strings.Join(message, " "))
	}

	return span
}

func StartOneShotSpan(name string) *Span {
	mu.Lock()
	defer mu.Unlock()

	span := &Span{
		name:      name,
		startTime: time.Now(),
		parent:    nil,
		depth:     0,
	}

	return span
}

// WithSpan executes the given function within a span and returns its result
func WithSpan[T any](name string, parent *Span, fn func(*Span) T) T {
	span := StartSpan(name, parent)
	defer span.End()
	return fn(span)
}

// End ends the span and prints its duration
func (s *Span) End() {
	duration := time.Since(s.startTime)
	indent := strings.Repeat("  ", s.depth)
	fmt.Printf("%s%s (%v)\n", indent, s.name, duration)
}

// End ends the span and prints its duration
func (s *Span) EndWithNewline() {
	s.End()
	fmt.Println()
}
