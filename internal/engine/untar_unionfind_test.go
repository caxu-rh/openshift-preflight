package engine

import (
	"slices"
	"testing"
)

func TestTarPathUnionFind_peersUnknownReturnsNil(t *testing.T) {
	t.Parallel()
	u := newTarPathUnionFind()
	if got := u.peers("never-seen"); got != nil {
		t.Fatalf("peers: got %#v, want nil", got)
	}
}

func TestTarPathUnionFind_unionEmptyIgnored(t *testing.T) {
	t.Parallel()
	u := newTarPathUnionFind()
	u.union("", "a")
	u.union("b", "")
	if u.peers("a") != nil || u.peers("b") != nil {
		t.Fatalf("expected no sets for a or b after union with empty string")
	}
	u.union("a", "b")
	want := []string{"a", "b"}
	slices.Sort(want)
	for _, label := range []struct {
		name string
		key  string
	}{
		{"a", "a"},
		{"b", "b"},
	} {
		got := u.peers(label.key)
		if got == nil {
			t.Fatalf("peers(%q): nil", label.key)
		}
		g := slices.Clone(got)
		slices.Sort(g)
		if !slices.Equal(g, want) {
			t.Fatalf("peers(%q): got %v want %v", label.key, got, want)
		}
	}
}

func TestTarPathUnionFind_unionMergesComponent(t *testing.T) {
	t.Parallel()
	u := newTarPathUnionFind()
	u.union("x", "y")
	u.union("y", "z")
	want := []string{"x", "y", "z"}
	slices.Sort(want)
	for _, key := range want {
		got := u.peers(key)
		if got == nil {
			t.Fatalf("peers(%q): nil", key)
		}
		g := slices.Clone(got)
		slices.Sort(g)
		if !slices.Equal(g, want) {
			t.Fatalf("peers(%q): got %v want %v", key, got, want)
		}
	}
	// Representatives agree after path compression.
	if u.find("x") != u.find("y") || u.find("y") != u.find("z") {
		t.Fatalf("find roots differ: x=%q y=%q z=%q", u.find("x"), u.find("y"), u.find("z"))
	}
}

func TestTarPathUnionFind_singletonPeers(t *testing.T) {
	t.Parallel()
	u := newTarPathUnionFind()
	u.ensure("only")
	got := u.peers("only")
	want := []string{"only"}
	if got == nil || !slices.Equal(got, want) {
		t.Fatalf("peers: got %#v want %#v", got, want)
	}
}
