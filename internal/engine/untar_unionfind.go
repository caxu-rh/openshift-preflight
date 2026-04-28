package engine

import "slices"

type tarPathUnionFind struct {
	parent  map[string]string
	members map[string][]string // root representative -> all paths in component (only for current roots)
}

func newTarPathUnionFind() *tarPathUnionFind {
	return &tarPathUnionFind{
		parent:  make(map[string]string),
		members: make(map[string][]string),
	}
}

func (u *tarPathUnionFind) ensure(x string) {
	if _, ok := u.parent[x]; ok {
		return
	}
	u.parent[x] = x
	u.members[x] = []string{x}
}

// find returns the canonical representative (root) of the disjoint set containing x, creating
// a singleton set for x if it has not been seen before. It applies path compression on the way up.
func (u *tarPathUnionFind) find(x string) string {
	u.ensure(x)
	p := u.parent[x]
	if p == x {
		return x
	}
	r := u.find(p)
	u.parent[x] = r
	return r
}

// union merges the sets containing a and b so they share the same representative. Empty strings
// are ignored.
func (u *tarPathUnionFind) union(a, b string) {
	if a == "" || b == "" {
		return
	}
	u.ensure(a)
	u.ensure(b)
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	u.parent[rb] = ra
	u.members[ra] = append(u.members[ra], u.members[rb]...)
	delete(u.members, rb)
}

// peers returns every tar path in the same hardlink equivalence class as x. If x was never
// inserted, peers returns nil.
func (u *tarPathUnionFind) peers(x string) []string {
	if _, ok := u.parent[x]; !ok {
		return nil
	}
	r := u.find(x)
	out := u.members[r]
	if len(out) == 0 {
		return nil
	}
	return slices.Clone(out)
}
