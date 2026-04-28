package engine

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/redhat-openshift-ecosystem/openshift-preflight/internal/log"
)

var (
	errLinkResolvesOutsideRoot = errors.New("link resolves to path outside of extraction root")
	errNilLinkIndex            = errors.New("untar: link index is required")
)

// expandLiteralPatternsWithDescendantGlob adds path/** for literals without glob metacharacters
// when no link index is available (legacy tests). For production, use expandLiteralPatternsWithDescendantGlobDedup
// with a link index so /** is never inferred from the archive: literals only gain path/** when
// path/** is already listed (exact files never get a spurious /**).
//
// Patterns containing `[` are skipped: we treat * ? [ as glob syntax; literal `[` in a path is rare.
func expandLiteralPatternsWithDescendantGlob(patterns []string) []string {
	if len(patterns) == 0 {
		return patterns
	}
	out, _ := expandLiteralPatternsWithDescendantGlobDedup(patterns, nil)
	return out
}

// literalShouldAppendDescendantGlob reports whether to add path/** for literal pattern path when
// idx is from the same archive; idx nil preserves legacy behavior (always true except skipped cases).
// When idx is set, descendant matching is opt-in only: path/** is added to the deduped set iff
// the incoming patterns already include an explicit cleanTarPath(path)+"/**" entry, so a
// directory or symlink-to-directory literal without /** does not pull in subpaths.
func literalShouldAppendDescendantGlob(idx *linkIndex, patterns []string, p string) bool {
	if idx == nil {
		return true
	}
	cleanP := cleanTarPath(p)
	if idx.regFileExactly(cleanP) {
		return false
	}
	want := cleanP + "/**"
	for _, q := range patterns {
		if cleanTarPath(q) == want {
			return true
		}
	}
	return false
}

// expandLiteralPatternsWithDescendantGlobDedup returns expanded patterns and a set of every
// non-empty pattern string for O(1) deduplication while appending symlink targets during extraction.
// When idx is non-nil, path/** is only added when patterns already list path/** (never inferred
// from directory or symlink-to-directory structure in the tar). idx nil keeps unconditional /** for literals.
func expandLiteralPatternsWithDescendantGlobDedup(patterns []string, idx *linkIndex) ([]string, map[string]struct{}) {
	out := slices.Clone(patterns)
	seen := make(map[string]struct{}, len(patterns)*2)
	for _, p := range patterns {
		if p != "" {
			seen[p] = struct{}{}
		}
	}
	for _, p := range patterns {
		if p == "" || strings.ContainsAny(p, "*?[") {
			continue
		}
		if !literalShouldAppendDescendantGlob(idx, patterns, p) {
			continue
		}
		var child string
		if idx == nil {
			child = p + "/**"
		} else {
			child = cleanTarPath(p) + "/**"
		}
		if _, ok := seen[child]; !ok {
			seen[child] = struct{}{}
			out = append(out, child)
		}
	}
	return out, seen
}

// unresolvedLinkTargetSatisfied reports whether extracted path ep satisfies unresolved key k:
// ep equals k or a strict descendant (directory targets), or when idx is set, the same for any
// hardlink peer of k in the tar index (symlink target names an alias of the extracted member).
func unresolvedLinkTargetSatisfied(k, ep string, idx *linkIndex) bool {
	if idx == nil {
		return ep == k || strings.HasPrefix(ep, k+"/")
	}
	for _, p := range idx.equivPaths(k) {
		if ep == p || strings.HasPrefix(ep, p+"/") {
			return true
		}
	}
	return false
}

// clearUnresolvedLinkTargetsForExtractedPath removes one entry from unresolved when the
// extracted path satisfies any key k: either ep equals k (exact), or ep is under k as
// k/... (strict descendant, e.g. directory symlink targets such as usr/share/licenses).
// Among all satisfied keys, it deletes the longest k by string length. When idx is non-nil,
// k is compared against ep via hardlink equivalence (see unresolvedLinkTargetSatisfied).
// idx may be nil (legacy tests).
func clearUnresolvedLinkTargetsForExtractedPath(unresolved map[string]struct{}, extractedPath string, idx *linkIndex) {
	ep := cleanTarPath(extractedPath)
	var longestKey string
	for k := range unresolved {
		if unresolvedLinkTargetSatisfied(k, ep, idx) {
			if len(k) > len(longestKey) {
				longestKey = k
			}
		}
	}
	if longestKey != "" {
		delete(unresolved, longestKey)
	}
}

// appendSymlinkTargetPatterns appends the resolved link target to filterPatterns when missing, and
// target/** only when the target is directory-like in the tar index and patternSeen already contains
// linkPath/** (descendant matching was requested for that link member). idx nil keeps legacy behavior
// of always appending target/**.
func appendSymlinkTargetPatterns(filterPatterns []string, patternSeen map[string]struct{}, logger logr.Logger, idx *linkIndex, linkPath, resolvedTargetName string) []string {
	nestedGlob := resolvedTargetName + "/**"
	if _, ok := patternSeen[resolvedTargetName]; !ok {
		patternSeen[resolvedTargetName] = struct{}{}
		logger.V(log.TRC).Info("adding symlink target path to filter patterns", "target", resolvedTargetName)
		filterPatterns = append(filterPatterns, resolvedTargetName)
	}
	addNested := idx == nil
	if idx != nil {
		_, linkHadDescendantGlob := patternSeen[cleanTarPath(linkPath)+"/**"]
		addNested = idx.directoryLikeForDescendantGlob(resolvedTargetName) && linkHadDescendantGlob
	}
	if addNested {
		if _, ok := patternSeen[nestedGlob]; !ok {
			patternSeen[nestedGlob] = struct{}{}
			logger.V(log.TRC).Info("adding symlink target descendant glob to filter patterns", "targetGlob", nestedGlob)
			filterPatterns = append(filterPatterns, nestedGlob)
		}
	}
	return filterPatterns
}

// closureSymlinkTargetPatterns applies appendSymlinkTargetPatterns for every link member that
// would be extracted under the current pattern set, repeating until stable so filterPatterns
// matches the fixed point of applyLinkSideEffects (ignoring extraction state). This reduces
// second full-layer passes when tar member order places matching files before symlinks that grow
// the pattern set.
func closureSymlinkTargetPatterns(filterPatterns []string, patternSeen map[string]struct{}, idx *linkIndex, logger logr.Logger) []string {
	if idx == nil {
		return filterPatterns
	}
	links := make([]string, 0, len(idx.linkMemberNames))
	for n := range idx.linkMemberNames {
		links = append(links, n)
	}
	slices.Sort(links)
	out := filterPatterns
	maxIter := max(len(idx.linkMemberNames)+8, 8)
	for iter := range maxIter {
		ps0, os0 := len(patternSeen), len(out)
		needed := idx.computeNeededLinkMembers(out)
		for _, name := range links {
			if !idx.shouldExtractSymlinkOrHardlink(name, out, needed) {
				continue
			}
			resolved := idx.resolvedTargetForLinkSideEffect(name)
			if resolved == "" {
				continue
			}
			out = appendSymlinkTargetPatterns(out, patternSeen, logger, idx, name, resolved)
		}
		if len(patternSeen) == ps0 && len(out) == os0 {
			break
		}
		if iter == maxIter-1 {
			logger.V(log.DBG).Info("symlink pattern closure hit iteration cap", "cap", maxIter)
		}
	}
	return out
}

// absJoinUnderRoot maps an in-archive relative path (forward slashes, no leading slash) under
// dstRoot and checks it stays inside the extraction root.
func absJoinUnderRoot(dstRoot *os.Root, rel string) (string, error) {
	if rel == "" || rel == "." {
		return "", errLinkResolvesOutsideRoot
	}
	finalOldname := filepath.Clean(filepath.Join(dstRoot.Name(), filepath.FromSlash(rel)))
	root := filepath.Clean(dstRoot.Name())
	if finalOldname != root && !strings.HasPrefix(finalOldname, root+string(os.PathSeparator)) {
		return "", errLinkResolvesOutsideRoot
	}
	return finalOldname, nil
}

// absResolvedSymlinkTarget maps a symlink tar Linkname to an absolute path on disk. Relative
// targets resolve from the link's directory; leading slashes are container-root-absolute, not
// host paths.
func absResolvedSymlinkTarget(dstRoot *os.Root, newname, oldname string) (string, error) {
	rel := resolveTarLinkTarget(newname, oldname)
	return absJoinUnderRoot(dstRoot, rel)
}

// absResolvedHardlinkTarget maps a hardlink tar Linkname to an absolute path on disk. Linkname
// names another archive member from the layer root; it is not resolved relative to the link path.
func absResolvedHardlinkTarget(dstRoot *os.Root, oldname string) (string, error) {
	rel := cleanTarPath(oldname)
	return absJoinUnderRoot(dstRoot, rel)
}

// symlinkTargetForRoot returns a symlink target string safe to pass to os.Root.Symlink: a path
// relative to the link's directory when the resolved target stays under dstRoot, otherwise an error.
func symlinkTargetForRoot(dstRoot *os.Root, newname, oldname string) (string, error) {
	absTarget, err := absResolvedSymlinkTarget(dstRoot, newname, oldname)
	if err != nil {
		return "", err
	}
	linkDir := filepath.Join(dstRoot.Name(), filepath.Dir(newname))
	rel, err := filepath.Rel(linkDir, absTarget)
	if err != nil {
		return "", err
	}
	return rel, nil
}

func hardlinkPathsStayUnderRoot(dstRoot *os.Root, oldname string) bool {
	_, err := absResolvedHardlinkTarget(dstRoot, oldname)
	return err == nil
}

func isRetryableLinkErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	var perr *os.PathError
	if errors.As(err, &perr) && os.IsNotExist(perr.Err) {
		return true
	}
	return false
}

type pendingLink struct {
	typeflag byte
	name     string
	linkname string
}

// untarPass holds mutable state for a single untarOnce invocation.
type untarPass struct {
	logger                   logr.Logger
	dstRoot                  *os.Root
	linkIdx                  *linkIndex
	state                    map[string]struct{}
	filterPatterns           []string
	patternSeen              map[string]struct{}
	neededLinks              map[string]struct{}
	filesProcessedInThisPass map[string]struct{}
	unresolvedLinkTargets    map[string]struct{}
	pendingLinks             []pendingLink
	tr                       *tar.Reader
	buf                      []byte
}

func (p *untarPass) refreshNeededLinks() {
	p.neededLinks = p.linkIdx.computeNeededLinkMembers(p.filterPatterns)
}

func (p *untarPass) headerMatches(header *tar.Header) bool {
	switch header.Typeflag {
	case tar.TypeReg:
		return p.linkIdx.memberMatchesPatterns(header.Name, p.filterPatterns)
	case tar.TypeSymlink, tar.TypeLink:
		return p.linkIdx.shouldExtractSymlinkOrHardlink(header.Name, p.filterPatterns, p.neededLinks)
	default:
		return false
	}
}

func (p *untarPass) applyLinkSideEffects(header *tar.Header) {
	if header.Typeflag != tar.TypeSymlink && header.Typeflag != tar.TypeLink {
		return
	}
	resolvedTargetName := p.linkIdx.resolvedTargetForLinkSideEffect(header.Name)
	if resolvedTargetName == "" {
		p.logger.V(log.TRC).Info("skipping link target not present in tar index", "link", header.Name, "typeflag", header.Typeflag)
		return
	}
	if header.Typeflag == tar.TypeSymlink {
		if _, ok := p.state[resolvedTargetName]; ok {
			return
		}
	} else {
		for _, peer := range p.linkIdx.equivPaths(resolvedTargetName) {
			if _, ok := p.state[peer]; ok {
				return
			}
		}
	}
	p.filterPatterns = appendSymlinkTargetPatterns(p.filterPatterns, p.patternSeen, p.logger, p.linkIdx, header.Name, resolvedTargetName)
	p.refreshNeededLinks()
	p.unresolvedLinkTargets[resolvedTargetName] = struct{}{}
}

func (p *untarPass) tryCreateLink(header *tar.Header) error {
	dirname := filepath.Dir(header.Name)
	if err := p.dstRoot.MkdirAll(dirname, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	switch header.Typeflag {
	case tar.TypeSymlink:
		target, err := symlinkTargetForRoot(p.dstRoot, header.Name, header.Linkname)
		if err != nil {
			return err
		}
		return p.dstRoot.Symlink(target, header.Name)
	case tar.TypeLink:
		if !hardlinkPathsStayUnderRoot(p.dstRoot, header.Linkname) {
			return errors.New("hardlink resolves outside extraction root")
		}
		oldMember := cleanTarPath(header.Linkname)
		return p.dstRoot.Link(filepath.FromSlash(oldMember), header.Name)
	default:
		return errors.New("unsupported link type")
	}
}

func (p *untarPass) drainPendingLinks() {
	// Replay deferred links until none succeed in a full pass. A small fixed minimum (8) bounds
	// work when few links reorder in a single sweep; len+2 covers one extra growth from side effects.
	maxPasses := max(len(p.pendingLinks)+2, 8)
	for pass := 0; pass < maxPasses && len(p.pendingLinks) > 0; pass++ {
		var still []pendingLink
		for _, pl := range p.pendingLinks {
			hdr := &tar.Header{
				Typeflag: pl.typeflag,
				Name:     pl.name,
				Linkname: pl.linkname,
			}
			if err := p.tryCreateLink(hdr); err != nil {
				still = append(still, pl)
				continue
			}
			p.filesProcessedInThisPass[pl.name] = struct{}{}
			p.state[pl.name] = struct{}{}
			clearUnresolvedLinkTargetsForExtractedPath(p.unresolvedLinkTargets, pl.name, p.linkIdx)
			p.applyLinkSideEffects(hdr)
		}
		p.pendingLinks = still
		if len(p.pendingLinks) == 0 {
			return
		}
	}
	if len(p.pendingLinks) > 0 {
		for _, pl := range p.pendingLinks {
			p.logger.V(log.DBG).Info("pending link could not be created after retries", "link", pl.name, "linkedTo", pl.linkname, "type", pl.typeflag)
		}
	}
}

func (p *untarPass) run() ([]string, error) {
	for {
		header, err := p.tr.Next()

		switch {
		case err == io.EOF:
			p.drainPendingLinks()
			p.logger.V(log.TRC).Info("extracted files", "files", p.filesProcessedInThisPass)
			p.logger.V(log.TRC).Info("remaining files", "files", p.unresolvedLinkTargets)
			return slices.Collect(maps.Keys(p.unresolvedLinkTargets)), nil

		case err != nil:
			//coverage:ignore
			p.logger.V(log.TRC).Info("extracted files", "files", p.filesProcessedInThisPass)
			p.logger.V(log.TRC).Info("remaining files", "files", p.unresolvedLinkTargets)
			return slices.Collect(maps.Keys(p.unresolvedLinkTargets)), err

		case header == nil:
			//coverage:ignore
			continue
		}

		if _, ok := p.state[header.Name]; ok {
			continue
		}

		if !p.headerMatches(header) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			//coverage:ignore
			continue

		case tar.TypeReg:
			dirname := filepath.Dir(header.Name)
			if err := p.dstRoot.MkdirAll(dirname, 0o755); err != nil && !os.IsExist(err) {
				return slices.Collect(maps.Keys(p.unresolvedLinkTargets)), err
			}

			fileMode := os.FileMode(header.Mode & 0o777)
			f, err := p.dstRoot.OpenFile(header.Name, os.O_CREATE|os.O_WRONLY, fileMode)
			if err != nil {
				//coverage:ignore
				return slices.Collect(maps.Keys(p.unresolvedLinkTargets)), err
			}

			if _, err := io.CopyBuffer(f, p.tr, p.buf); err != nil {
				//coverage:ignore
				f.Close()
				return slices.Collect(maps.Keys(p.unresolvedLinkTargets)), err
			}

			p.filesProcessedInThisPass[header.Name] = struct{}{}
			p.state[header.Name] = struct{}{}
			clearUnresolvedLinkTargetsForExtractedPath(p.unresolvedLinkTargets, header.Name, p.linkIdx)
			f.Close()

		case tar.TypeSymlink, tar.TypeLink:
			if err := p.tryCreateLink(header); err != nil {
				if isRetryableLinkErr(err) {
					p.logger.V(log.DBG).Info("deferring link creation", "link", header.Name, "linkedTo", header.Linkname, "type", header.Typeflag, "reason", err.Error())
					p.pendingLinks = append(p.pendingLinks, pendingLink{
						typeflag: header.Typeflag,
						name:     header.Name,
						linkname: header.Linkname,
					})
				} else {
					p.logger.V(log.DBG).Info("error creating link, ignoring", "link", header.Name, "linkedTo", header.Linkname, "type", header.Typeflag, "reason", err.Error())
				}
				continue
			}

			p.filesProcessedInThisPass[header.Name] = struct{}{}
			p.state[header.Name] = struct{}{}
			clearUnresolvedLinkTargetsForExtractedPath(p.unresolvedLinkTargets, header.Name, p.linkIdx)
			p.applyLinkSideEffects(header)

		default:
			if header.Size > 0 {
				if _, err := io.CopyN(io.Discard, p.tr, header.Size); err != nil {
					return slices.Collect(maps.Keys(p.unresolvedLinkTargets)), err
				}
			}
		}
	}
}

// untar takes a destination path, a container image, and a list of files or match patterns
// which should be extracted out of the image.
func untar(ctx context.Context, dst string, img v1.Image, requiredFilePatterns []string) error {
	logger := logr.FromContextOrDiscard(ctx)
	logger.V(log.DBG).Info("exporting and flattening image")

	// Extract all files matching the required file patterns.
	state := make(map[string]struct{})
	var err error

	logger.V(log.DBG).Info("extracting container filesystem", "path", dst)

	remaining := slices.Clone(requiredFilePatterns)

	// Read the full layer once up front for link/symlink/hardlink metadata. Each untarOnce pass
	// reads the layer again via mutate.Extract; that double read is intentional so matching uses
	// a complete index before stream-order-sensitive extraction.
	idxReader := mutate.Extract(img)
	linkIdx, idxErr := buildLinkIndex(idxReader)
	_ = idxReader.Close()
	if idxErr != nil {
		return fmt.Errorf("failed to extract tarball: index tar links: %w", idxErr)
	}

	// In the case of symlinks, the targets may not be included in the original required file
	// patterns, so make additional passes through the layers as needed to find them.
	// Make at least one pass to validate the tar format, even if there are no required patterns.
	for {
		if remaining, err = untarOnce(ctx, dst, img, remaining, state, linkIdx); err != nil {
			return fmt.Errorf("failed to extract tarball: %w", err)
		}
		if len(remaining) == 0 {
			break
		}
	}

	return nil
}

// untarOnce takes a destination path, a container image, a list of files or match patterns
// which should be extracted out of the image, and a map in which to store extraction progress/state.
// The function returns a list of files that should be extracted in another invocation of
// untarOnce along with an error if one was encountered.
// linkIdx must be non-nil (build it with buildLinkIndex on the same image/layer).
// A tar reader loops over the tarfile creating the file structure at
// 'dst' along the way, and writing any files. This function uses a pre-allocated buffer to
// reduce allocations and is not goroutine-safe.
// Uses os.Root to restrict extraction to dst.
func untarOnce(ctx context.Context, dst string, img v1.Image, filterPatterns []string, state map[string]struct{}, linkIdx *linkIndex) (remaining []string, err error) {
	if linkIdx == nil {
		return nil, errNilLinkIndex
	}
	logger := logr.FromContextOrDiscard(ctx)
	filterPatterns, patternSeen := expandLiteralPatternsWithDescendantGlobDedup(filterPatterns, linkIdx)
	filterPatterns = closureSymlinkTargetPatterns(filterPatterns, patternSeen, linkIdx, logger)
	logger.V(log.TRC).Info("extracting from tar stream with filter patterns", "patterns", filterPatterns)

	neededLinks := linkIdx.computeNeededLinkMembers(filterPatterns)

	fs := mutate.Extract(img)
	defer func() {
		_, drainErr := io.Copy(io.Discard, fs)
		if drainErr != nil && err == nil {
			err = fmt.Errorf("failed to drain io reader: %w", drainErr)
		}
		fs.Close()
	}()

	filesProcessedInThisPass := make(map[string]struct{})
	unresolvedLinkTargets := make(map[string]struct{})

	tr := tar.NewReader(fs)
	dst = filepath.Clean(dst)
	dstRoot, openErr := os.OpenRoot(dst)
	if openErr != nil {
		//coverage:ignore
		return slices.Collect(maps.Keys(unresolvedLinkTargets)), fmt.Errorf("untar error, unable to open extraction destination %s: %w", dst, openErr)
	}
	defer dstRoot.Close()

	pass := &untarPass{
		logger:                   logger,
		dstRoot:                  dstRoot,
		linkIdx:                  linkIdx,
		state:                    state,
		filterPatterns:           filterPatterns,
		patternSeen:              patternSeen,
		neededLinks:              neededLinks,
		filesProcessedInThisPass: filesProcessedInThisPass,
		unresolvedLinkTargets:    unresolvedLinkTargets,
		tr:                       tr,
		buf:                      make([]byte, 256*1024),
	}
	return pass.run()
}

// resolveLinkPaths is only for the legacy "Link Path Resolution" table tests in untar_test.go.
// Production extraction resolves symlink targets with resolveTarLinkTarget and symlinkTargetForRoot.
//
// resolveLinkPaths determines if oldname is an absolute path or a relative
// path, and returns oldname relative to newname if necessary.
func resolveLinkPaths(oldname, newname string) (string, string) {
	if filepath.IsAbs(oldname) {
		return oldname, newname
	}

	linkDir := filepath.Dir(newname)
	if linkDir == "." {
		linkDir = "/"
	}

	return filepath.Join(linkDir, oldname), newname
}
