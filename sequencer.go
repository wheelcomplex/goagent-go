package main

import (
	"sync"
)

type sequencer struct {
	mu     sync.Mutex
	id     uint
	wait   map[uint]chan bool
	closed bool
}

// Start waits until it is time for the event numbered id to begin.
// That is, except for the first event, it waits until End(id-1) has
// been called.
func (s *sequencer) Start(id uint) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	if s.id == id {
		s.mu.Unlock()
		return true
	}
	c := make(chan bool)
	if s.wait == nil {
		s.wait = make(map[uint]chan bool)
	}
	s.wait[id] = c
	s.mu.Unlock()
	return <-c
}

// End notifies the sequencer that the event numbered id has completed,
// allowing it to schedule the event numbered id+1.  It is a run-time error
// to call End with an id that is not the number of the active event.
func (s *sequencer) End(id uint) {
	s.mu.Lock()
	if s.id != id {
		panic("out of sync")
	}
	id++
	s.id = id
	if s.wait == nil {
		s.wait = make(map[uint]chan bool)
	}
	c, ok := s.wait[id]
	if ok {
		delete(s.wait, id)
	}
	s.mu.Unlock()
	if ok {
		c <- true
	}
}

func (s *sequencer) Close() {
	s.mu.Lock()
	for _, c := range s.wait {
		close(c)
	}
	s.wait = nil
	s.mu.Unlock()
}
