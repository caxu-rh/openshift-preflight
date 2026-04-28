package engine

import (
	"archive/tar"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// linkIndex captures symlink targets and hardlink groupings from a tar stream so extraction can
// match logical paths (through symlinks and hardlinks) against physical member names.
type linkIndex struct {
	symlinks         map[string]string   // link path -> raw Linkname from tar
	hardlinks        map[string]string   // TypeLink member path -> raw Linkname from tar
	regPaths         []string            // paths of regular file members (stable iteration order)
	regSet           map[string]struct{} // cleanTarPath reg member -> struct{}
	linkMemberNames  map[string]struct{} // tar member names that are TypeSymlink or TypeLink
	symlinksByTarget map[string][]string // resolved symlink target -> symlink member names
	uf               *tarPathUnionFind
}

// equivPaths returns {x} merged with hardlink peers of x when x participates in a hardlink group;
// otherwise it returns a single-element slice containing x.
func (idx *linkIndex) equivPaths(x string) []string {
	if peers := idx.uf.peers(x); len(peers) > 0 {
		return peers
	}
	return []string{x}
}

// cleanTarPath normalizes tar path names to a clean slash-separated form without a leading slash.
// It must not strip leading ".." segments (e.g. "../evil") or traversal regression tests and
// OpenRoot path checks will not run.
func cleanTarPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	return path.Clean(p)
}

func doublestarMatchAny(patterns []string, path string) bool {
	for _, pat := range patterns {
		if ok, _ := doublestar.Match(pat, path); ok {
			return true
		}
	}
	return false
}

// resolveTarLinkTarget resolves oldname (tar Linkname) relative to linkPath (the link member Name).
func resolveTarLinkTarget(linkPath, oldname string) string {
	if strings.HasPrefix(oldname, "/") {
		return cleanTarPath(oldname)
	}
	dir := path.Dir(linkPath)
	if dir == "." {
		dir = ""
	}
	return cleanTarPath(path.Join(dir, oldname))
}

// symlinkPeersWithSameRaw returns symlink member paths in the same hardlink group as linkPath
// that share the same raw Linkname. Used so relative targets resolve from an alias that names
// real archive members, not from a peer dirname that yields a nonexistent path.
func (idx *linkIndex) symlinkPeersWithSameRaw(linkPath string) []string {
	lp := cleanTarPath(linkPath)
	raw, ok := idx.symlinks[lp]
	if !ok {
		return []string{lp}
	}
	peers := idx.uf.peers(lp)
	if len(peers) == 0 {
		return []string{lp}
	}
	var out []string
	seen := make(map[string]struct{}, len(peers))
	for _, m := range peers {
		if idx.symlinks[m] != raw {
			continue
		}
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	if len(out) == 0 {
		return []string{lp}
	}
	slices.Sort(out)
	return out
}

func (idx *linkIndex) hasRegMemberAtOrBelow(prefix string) bool {
	if prefix == "" || prefix == "." {
		return false
	}
	for _, r := range idx.regPaths {
		if r == prefix || strings.HasPrefix(r, prefix+"/") {
			return true
		}
	}
	return false
}

// hasRegMemberStrictlyBelow reports whether any regular file path is a strict descendant of prefix.
func (idx *linkIndex) hasRegMemberStrictlyBelow(prefix string) bool {
	prefix = cleanTarPath(prefix)
	if prefix == "" || prefix == "." {
		return false
	}
	for _, r := range idx.regPaths {
		if strings.HasPrefix(r, prefix+"/") {
			return true
		}
	}
	return false
}

// hasIndexedMemberAtOrBelow reports whether any regular file or symlink/hardlink tar member is
// exactly at prefix or under prefix/ (prefix is a clean archive-relative path).
func (idx *linkIndex) hasIndexedMemberAtOrBelow(prefix string) bool {
	if prefix == "" || prefix == "." {
		return false
	}
	if idx.hasRegMemberAtOrBelow(prefix) {
		return true
	}
	for name := range idx.linkMemberNames {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

// resolvedTargetHasIndexedSubtree reports whether prefix or any hardlink peer of prefix has an
// indexed member at that path or beneath it (so symlink/hardlink targets that name only an inode
// alias still match content stored under a peer path).
func (idx *linkIndex) resolvedTargetHasIndexedSubtree(resolved string) bool {
	resolved = cleanTarPath(resolved)
	if resolved == "" || resolved == "." {
		return false
	}
	return slices.ContainsFunc(idx.equivPaths(resolved), idx.hasIndexedMemberAtOrBelow)
}

// resolvedSymlinkTargetForPatterns returns the archive-relative path to use for filter patterns
// and unresolved symlink passes. Relative Linknames are evaluated from symlinkPeersWithSameRaw
// until one resolves to a prefix that names indexed tar content; otherwise resolves from linkPath
// only when that path also names indexed content. Returns "" when the target names nothing in
// the index.
func (idx *linkIndex) resolvedSymlinkTargetForPatterns(linkPath, raw string) string {
	if strings.HasPrefix(raw, "/") {
		resolved := cleanTarPath(raw)
		if idx.resolvedTargetHasIndexedSubtree(resolved) {
			return resolved
		}
		return ""
	}
	lp := cleanTarPath(linkPath)
	for _, m := range idx.symlinkPeersWithSameRaw(lp) {
		resolved := cleanTarPath(resolveTarLinkTarget(m, raw))
		if resolved != "" && idx.resolvedTargetHasIndexedSubtree(resolved) {
			return resolved
		}
	}
	resolvedFromLink := cleanTarPath(resolveTarLinkTarget(lp, raw))
	if resolvedFromLink == "" {
		return ""
	}
	if idx.resolvedTargetHasIndexedSubtree(resolvedFromLink) {
		return resolvedFromLink
	}
	return ""
}

// resolvedTargetForLinkSideEffect returns the archive-relative target path used when augmenting
// filter patterns after extracting a symlink or hardlink member, or "" when the link does not
// name indexed content. linkMemberPath must be a path present in linkMemberNames. For symlinks,
// non-empty results are exactly those from resolvedSymlinkTargetForPatterns (already restricted
// to targets that name indexed archive content).
func (idx *linkIndex) resolvedTargetForLinkSideEffect(linkMemberPath string) string {
	name := cleanTarPath(linkMemberPath)
	if raw, ok := idx.symlinks[name]; ok {
		return idx.resolvedSymlinkTargetForPatterns(name, raw)
	}
	if raw, ok := idx.hardlinks[name]; ok {
		resolved := cleanTarPath(raw)
		if resolved == "" || !idx.resolvedTargetHasIndexedSubtree(resolved) {
			return ""
		}
		return resolved
	}
	return ""
}

// buildLinkIndex reads an entire tar stream once and returns link metadata for matching.
func buildLinkIndex(r io.Reader) (*linkIndex, error) {
	tr := tar.NewReader(r)
	idx := &linkIndex{
		symlinks:         make(map[string]string),
		hardlinks:        make(map[string]string),
		regSet:           make(map[string]struct{}),
		linkMemberNames:  make(map[string]struct{}),
		symlinksByTarget: make(map[string][]string),
		uf:               newTarPathUnionFind(),
	}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header == nil {
			continue
		}
		name := cleanTarPath(header.Name)
		if name == "" || name == "." {
			continue
		}

		switch header.Typeflag {
		case tar.TypeSymlink:
			idx.symlinks[name] = header.Linkname
			idx.linkMemberNames[name] = struct{}{}
		case tar.TypeLink:
			idx.linkMemberNames[name] = struct{}{}
			idx.hardlinks[name] = header.Linkname
			target := cleanTarPath(header.Linkname)
			idx.uf.union(name, target)
		case tar.TypeReg:
			idx.regPaths = append(idx.regPaths, name)
			idx.regSet[name] = struct{}{}
			if _, err := io.CopyN(io.Discard, tr, header.Size); err != nil {
				return nil, err
			}
		default:
			if header.Typeflag == tar.TypeDir {
				continue
			}
			if header.Size > 0 {
				if _, err := io.CopyN(io.Discard, tr, header.Size); err != nil {
					return nil, err
				}
			}
		}
	}
	idx.propagateSymlinksToHardlinkPeers()
	idx.rebuildSymlinksByTarget()
	return idx, nil
}

func (idx *linkIndex) rebuildSymlinksByTarget() {
	idx.symlinksByTarget = make(map[string][]string, len(idx.symlinks))
	for sym, raw := range idx.symlinks {
		resolved := resolveTarLinkTarget(sym, raw)
		if resolved != "" {
			idx.symlinksByTarget[resolved] = append(idx.symlinksByTarget[resolved], sym)
		}
	}
}

// propagateSymlinksToHardlinkPeers copies symlink linknames onto every hard-link peer path so
// alias expansion sees the same logical target from e.g. usr/lib/sysimage/rpm as from the
// OSTree sysroot/.../hash.file symlink it is hard-linked to.
func (idx *linkIndex) propagateSymlinksToHardlinkPeers() {
	added := make(map[string]string)
	for sym, raw := range idx.symlinks {
		for _, peer := range idx.uf.peers(sym) {
			if peer == sym {
				continue
			}
			if _, exists := idx.symlinks[peer]; exists {
				continue
			}
			added[peer] = raw
			idx.linkMemberNames[peer] = struct{}{}
		}
	}
	maps.Copy(idx.symlinks, added)
}

// regFileExactly reports whether path is exactly the name of a regular-file member in the index
// (after cleanTarPath normalization).
func (idx *linkIndex) regFileExactly(path string) bool {
	_, ok := idx.regSet[cleanTarPath(path)]
	return ok
}

// followSymlinkChain resolves path through symlink members in the index until a non-symlink path
// or a cycle is reached.
func (idx *linkIndex) followSymlinkChain(path string) string {
	seen := make(map[string]struct{})
	p := cleanTarPath(path)
	for {
		if p == "" || p == "." {
			return p
		}
		if _, dup := seen[p]; dup {
			return p
		}
		seen[p] = struct{}{}
		raw, ok := idx.symlinks[p]
		if !ok {
			return p
		}
		next := cleanTarPath(resolveTarLinkTarget(p, raw))
		if next == "" {
			return p
		}
		p = next
	}
}

// directoryLikeForDescendantGlob reports whether path may have nested regular files under it in
// the archive (implicit directory prefix or symlink chain ending at such a prefix), excluding
// exact regular files and symlink chains that end at a regular file.
func (idx *linkIndex) directoryLikeForDescendantGlob(path string) bool {
	end := idx.followSymlinkChain(path)
	if end == "" || end == "." {
		return false
	}
	if idx.regFileExactly(end) {
		return false
	}
	return idx.hasRegMemberStrictlyBelow(end)
}

// expandAliases returns every tar path that refers to the same content as member for pattern
// matching: hardlink peers, inverse directory symlinks (logical paths under symlink targets),
// and symlink-to-file aliases except where skipped to avoid false positives (e.g. multi-pass
// symlink resolution or symlink-to-symlink consumer edges).
func (idx *linkIndex) expandAliases(member string) []string {
	member = cleanTarPath(member)
	visited := make(map[string]struct{})
	queue := []string{member}
	var out []string

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if _, ok := visited[cur]; ok {
			continue
		}
		visited[cur] = struct{}{}
		out = append(out, cur)

		for _, peer := range idx.uf.peers(cur) {
			if _, ok := visited[peer]; !ok {
				queue = append(queue, peer)
			}
		}

		for d := cur; d != "" && d != "."; d = path.Dir(d) {
			for _, symName := range idx.symlinksByTarget[d] {
				raw := idx.symlinks[symName]
				resolved := resolveTarLinkTarget(symName, raw)
				if resolved == "" {
					continue
				}
				var alt string
				switch {
				case cur == resolved:
					if _, isSymlinkMember := idx.symlinks[cur]; isSymlinkMember {
						continue
					}
					if idx.regFileExactly(resolved) {
						continue
					}
					alt = symName
				case strings.HasPrefix(cur, resolved+"/"):
					alt = cleanTarPath(path.Join(symName, strings.TrimPrefix(cur[len(resolved):], "/")))
				default:
					continue
				}
				if _, ok := visited[alt]; !ok {
					queue = append(queue, alt)
				}
			}
		}
	}
	return out
}

// aliasesMatchAnyPattern reports whether any path in aliases matches any filter pattern
// (doublestar). Shared by memberMatchesPatterns and computeNeededLinkMembers so expandAliases
// runs at most once per regular-file member per call site.
func aliasesMatchAnyPattern(aliases []string, patterns []string) bool {
	return slices.ContainsFunc(aliases, func(alias string) bool {
		return doublestarMatchAny(patterns, alias)
	})
}

// memberMatchesPatterns reports whether any filter pattern matches member or one of its
// expandAliases paths using doublestar.Match. Used for regular file members.
func (idx *linkIndex) memberMatchesPatterns(member string, patterns []string) bool {
	return aliasesMatchAnyPattern(idx.expandAliases(cleanTarPath(member)), patterns)
}

// linkPathDirectMatch matches patterns against a symlink/hardlink member name and its hardlink
// peers only. It must not apply symlink inverse expansion (that is only for regular files), or
// a symlink that points *to* this path would incorrectly satisfy unrelated patterns.
func (idx *linkIndex) linkPathDirectMatch(name string, patterns []string) bool {
	n := cleanTarPath(name)
	candidates := append([]string{n}, idx.uf.peers(n)...)
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		if doublestarMatchAny(patterns, c) {
			return true
		}
	}
	return false
}

// aliasRelevantForLinkExtraction reports whether alias should participate in link-header discovery
// for a regular file reg that already matched patterns. Not every path in expandAliases(reg) matches
// the same glob (e.g. hardlink peers), but those aliases can still sit on paths that require
// extracting symlinks whose targets name another peer.
func (idx *linkIndex) aliasRelevantForLinkExtraction(reg, alias string, patterns []string) bool {
	a := cleanTarPath(alias)
	if doublestarMatchAny(patterns, a) {
		return true
	}
	for _, p := range idx.equivPaths(reg) {
		if cleanTarPath(p) == a {
			return true
		}
	}
	if raw, ok := idx.symlinks[a]; ok {
		t := resolveTarLinkTarget(a, raw)
		if doublestarMatchAny(patterns, t) {
			return true
		}
		for _, p := range idx.equivPaths(reg) {
			if cleanTarPath(p) == t {
				return true
			}
		}
	}
	return false
}

// pathUsesLinkOnPath reports whether aliasPath traverses linkPath as a path component: aliasPath
// equals linkPath or a hardlink peer of it, or some parent directory of aliasPath (by path.Dir)
// equals linkPath or a peer. Used to decide if a symlink/hardlink header must be extracted when a
// regular file already matches the filter.
func (idx *linkIndex) pathUsesLinkOnPath(aliasPath, linkPath string) bool {
	lp := cleanTarPath(linkPath)
	ap := cleanTarPath(aliasPath)
	targets := map[string]struct{}{lp: {}}
	for _, p := range idx.uf.peers(lp) {
		targets[p] = struct{}{}
	}
	if _, ok := targets[ap]; ok {
		return true
	}
	for d := ap; d != "." && d != ""; d = path.Dir(d) {
		if _, ok := targets[d]; ok {
			return true
		}
	}
	return false
}

// linkHeaderNeeded reports whether a symlink or hardlink member must be materialized so that a
// matched regular file can be reached through a logical path that traverses this link.
//
// This is the reference formulation of the predicate. Production extraction uses
// computeNeededLinkMembers instead: that batch builds a map in one pass over regPaths so each
// tar header check is O(1) in the map. The two must stay equivalent; see
// TestComputeNeededLinkMembersMatchesLinkHeaderNeeded in untar_index_needed_test.go.
func (idx *linkIndex) linkHeaderNeeded(name string, patterns []string) bool {
	ln := cleanTarPath(name)
	for _, reg := range idx.regPaths {
		aliases := idx.expandAliases(reg)
		if !aliasesMatchAnyPattern(aliases, patterns) {
			continue
		}
		for _, alias := range aliases {
			if !idx.aliasRelevantForLinkExtraction(reg, alias, patterns) {
				continue
			}
			if idx.pathUsesLinkOnPath(alias, ln) {
				return true
			}
		}
	}
	return false
}

// computeNeededLinkMembers returns the set of symlink/hardlink tar member names that must be
// extracted so matched regular files remain reachable through logical paths (same predicate as
// linkHeaderNeeded, precomputed once per pattern set).
//
// linkHeaderNeeded answers the same question for one link name but would repeat the inner work
// for every header if used on the hot path; this function inverts the loop once per pattern set.
// Equivalence is enforced by TestComputeNeededLinkMembersMatchesLinkHeaderNeeded.
func (idx *linkIndex) computeNeededLinkMembers(patterns []string) map[string]struct{} {
	needed := make(map[string]struct{})
	for _, reg := range idx.regPaths {
		aliases := idx.expandAliases(reg)
		if !aliasesMatchAnyPattern(aliases, patterns) {
			continue
		}
		for _, alias := range aliases {
			if !idx.aliasRelevantForLinkExtraction(reg, alias, patterns) {
				continue
			}
			ap := cleanTarPath(alias)
			for d := ap; d != "" && d != "."; d = path.Dir(d) {
				for _, x := range idx.equivPaths(d) {
					if _, ok := idx.linkMemberNames[x]; ok {
						needed[x] = struct{}{}
					}
				}
			}
		}
	}
	return needed
}

// shouldExtractSymlinkOrHardlink reports whether a symlink or hardlink tar member should be
// written: the path matches patterns directly (with hardlink peers only), or it appears in
// neededLinks from computeNeededLinkMembers for this pass.
func (idx *linkIndex) shouldExtractSymlinkOrHardlink(name string, patterns []string, neededLinks map[string]struct{}) bool {
	ln := cleanTarPath(name)
	if idx.linkPathDirectMatch(ln, patterns) {
		return true
	}
	_, ok := neededLinks[ln]
	return ok
}
