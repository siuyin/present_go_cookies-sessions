package main

import (
	"testing"
	"time"
)

func TestMemCache(t *testing.T) {
	m := NewMemCache()
	defer m.Stop()
	m.h["a"] = []byte("apple")
	if string(m.h["a"]) != "apple" {
		t.Error("map look-up failed")
	}
}
func TestMemCacheSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping garbageCollect test in short mode")
	}
	m := NewMemCache()
	defer m.Stop()
	m.Set("a", []byte("apple"), time.Now().Add(1500*time.Millisecond))
	m.Set("b", []byte("boy"), time.Now().Add(500*time.Millisecond))
	a, ok := m.Get("a")
	if string(a) != "apple" || !ok {
		t.Error("Set / Get failed")
	}
	a, ok = m.Get("b")
	if string(a) != "boy" || !ok {
		t.Error("Set / Get failed")
	}
	time.Sleep(1010 * time.Millisecond) // the tick is 1 sec.
	_, ok = m.Get("a")
	if !ok {
		t.Error("garbageCollect failed")
	}
	_, ok = m.Get("b")
	if ok {
		t.Error("garbageCollect failed")
	}
}

func TestSessStore(t *testing.T) {
	ss := NewSessStore(30 * time.Second)
	if ss.GCInterval != 30*time.Second {
		t.Errorf("gc interval set failed: %q", ss.GCInterval)
	}

	ss.Set(Session{"abc", "tom", time.Now().Add(30 * time.Minute), 30 * time.Minute})
	_, ok := ss.Get("abc")
	if !ok {
		t.Errorf("get fail")
	}

	ss.Delete("abc")
	_, ok = ss.Get("abc")
	if ok {
		t.Errorf("delete failed")
	}

	ss.Set(Session{"def", "tom", time.Now().Add(time.Nanosecond), time.Nanosecond}) // this lasts only 1ns
	ss.GC()
	_, ok = ss.Get("def")
	if ok {
		t.Errorf("garbage collect failed")
	}
}
