package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/go-logr/logr"
)

func writeTarSymlinkToDirWithNestedFile(out *bytes.Buffer, content []byte) error {
	tw := tar.NewWriter(out)
	defer tw.Close()
	if err := tw.WriteHeader(&tar.Header{Name: "targetdir/nested/f.txt", Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "entry", Typeflag: tar.TypeSymlink, Linkname: "targetdir", Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		return err
	}
	return nil
}

func TestExpandLiteralDedupExactFileNoDescendantGlob(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "deep/path/file.txt", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{"deep/path/file.txt"}, idx)
	want := []string{"deep/path/file.txt"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandLiteralDedupImplicitDirWithoutExplicitChild(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "mydir/nested/x.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{"mydir"}, idx)
	want := []string{"mydir"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandLiteralDedupImplicitDirWithExplicitChild(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "mydir/nested/x.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{"mydir", "mydir/**"}, idx)
	want := []string{"mydir", "mydir/**"}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandLiteralDedupSymlinkToDirWithoutExplicitChild(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeTarSymlinkToDirWithNestedFile(&buf, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{"entry"}, idx)
	want := []string{"entry"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandLiteralDedupSymlinkToDirWithExplicitChild(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeTarSymlinkToDirWithNestedFile(&buf, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{"entry", "entry/**"}, idx)
	want := []string{"entry", "entry/**"}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestClosureSymlinkTargetPatternsAddsResolvedTarget(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("payload")
	regPath := "deep/real/nested/f.txt"
	if err := tw.WriteHeader(&tar.Header{Name: regPath, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "entry", Typeflag: tar.TypeSymlink, Linkname: "deep/real", Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	fp := []string{"entry/nested/f.txt"}
	fp, seen := expandLiteralPatternsWithDescendantGlobDedup(fp, idx)
	fp = closureSymlinkTargetPatterns(fp, seen, idx, logr.Discard())
	if _, ok := seen["deep/real"]; !ok {
		t.Fatalf("closure should add symlink target to patternSeen; seen keys=%v fp=%v", mapsKeys(seen), fp)
	}
	if !slices.Contains(fp, "deep/real") {
		t.Fatalf("expected deep/real in filter patterns, got %v", fp)
	}
}

func TestUntarFileBeforeSymlinkExtractedViaPatternClosure(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("layer-payload")
	regPath := "deep/real/nested/f.txt"
	if err := tw.WriteHeader(&tar.Header{Name: regPath, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "entry", Typeflag: tar.TypeSymlink, Linkname: "deep/real", Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	img, err := createImageWithLayer(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := untar(context.Background(), tmpDir, img, []string{"entry/nested/f.txt"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(tmpDir, regPath))
	if err != nil {
		t.Fatalf("read physical path: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content: got %q want %q", got, content)
	}
	got, err = os.ReadFile(filepath.Join(tmpDir, "entry", "nested", "f.txt"))
	if err != nil {
		t.Fatalf("read via symlink path: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("via symlink: got %q want %q", got, content)
	}
}

func TestAppendSymlinkTargetPatternsDescendantOptIn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeTarSymlinkToDirWithNestedFile(&buf, []byte("x")); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("with_link_path_descendant_glob", func(t *testing.T) {
		seen := map[string]struct{}{
			"entry":     {},
			"entry/**":  {},
			"targetdir": {},
		}
		fp := []string{"entry", "entry/**", "targetdir"}
		out := appendSymlinkTargetPatterns(slices.Clone(fp), seen, logr.Discard(), idx, "entry", "targetdir")
		if !slices.Contains(out, "targetdir/**") {
			t.Fatalf("expected targetdir/** in %v", out)
		}
	})
	t.Run("without_link_path_descendant_glob", func(t *testing.T) {
		seen := map[string]struct{}{
			"entry":     {},
			"targetdir": {},
		}
		fp := []string{"entry", "targetdir"}
		out := appendSymlinkTargetPatterns(slices.Clone(fp), seen, logr.Discard(), idx, "entry", "targetdir")
		if slices.Contains(out, "targetdir/**") {
			t.Fatalf("did not want targetdir/** in %v", out)
		}
	})
}

func TestLinkIndexOstreeLinkHeaderNeeded(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	content := []byte("rpm database content")
	if err := writeOstreeRPMTestFixture(&buf, content); err != nil {
		t.Fatal(err)
	}

	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	patterns, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{testOstreeExtractPattern}, idx)
	if !idx.memberMatchesPatterns(testOstreeRPMDBPath, patterns) {
		t.Fatal("expected physical reg path to match via symlink/hardlink aliases")
	}
	if !idx.linkHeaderNeeded(testOstreeObjectSymlinkPath, patterns) {
		t.Fatal("expected hash.file symlink to be needed")
	}
	needed := idx.computeNeededLinkMembers(patterns)
	if !idx.shouldExtractSymlinkOrHardlink(testOstreeObjectSymlinkPath, patterns, needed) {
		t.Fatal("expected hash.file to be extracted")
	}
}

func TestLinkIndexSymlinkToHardlinkPeerAlias(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	content := []byte("payload")
	chain := []linkChainEntry{
		{name: "short/file", linkType: hardlink, target: "deep/path/file"},
		{name: "consumer", linkType: symlink, target: "short/file"},
	}
	if err := writeTarballWithLinkChain(&buf, content, "deep/path/file", chain, false); err != nil {
		t.Fatal(err)
	}

	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	patterns, _ := expandLiteralPatternsWithDescendantGlobDedup([]string{"deep/path/file"}, idx)
	if !idx.memberMatchesPatterns("deep/path/file", patterns) {
		t.Fatal("expected reg member to match")
	}
	if !idx.linkHeaderNeeded("consumer", patterns) {
		t.Fatal("expected symlink consumer to be needed when it targets a hardlink peer not matched by the glob")
	}
	needed := idx.computeNeededLinkMembers(patterns)
	if _, ok := needed["consumer"]; !ok {
		t.Fatal("expected consumer in computeNeededLinkMembers")
	}
	if !idx.shouldExtractSymlinkOrHardlink("consumer", patterns, needed) {
		t.Fatal("expected consumer symlink to be extracted")
	}

	for ln := range idx.linkMemberNames {
		want := idx.linkHeaderNeeded(ln, patterns)
		_, got := needed[ln]
		if want != got {
			t.Fatalf("link %q: linkHeaderNeeded=%v computeNeeded=%v", ln, want, got)
		}
	}
}

func TestClearUnresolvedLinkTargetsHardlinkPeer(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	content := []byte("payload")
	chain := []linkChainEntry{
		{name: "alias/file", linkType: hardlink, target: "deep/path/file"},
	}
	if err := writeTarballWithLinkChain(&buf, content, "deep/path/file", chain, false); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	u := map[string]struct{}{"alias/file": {}}
	clearUnresolvedLinkTargetsForExtractedPath(u, "deep/path/file", idx)
	if len(u) != 0 {
		t.Fatalf("expected unresolved cleared via hardlink peer, got keys %v", u)
	}
}

func TestResolvedSymlinkTargetForPatternsSymlinkPeers(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	content := []byte("idx")
	if err := writeTarSymlinkHardlinkPeersBadSymlinkFirst(&buf, content); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw := "../target/data.txt"
	if got := idx.resolvedSymlinkTargetForPatterns("bad/deep/sym", raw); got != "target/data.txt" {
		t.Fatalf("bad peer: got %q want target/data.txt", got)
	}
	if got := idx.resolvedSymlinkTargetForPatterns("good/sym", raw); got != "target/data.txt" {
		t.Fatalf("good peer: got %q want target/data.txt", got)
	}
}

func TestResolvedSymlinkTargetForPatternsDanglingRelative(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "real.txt", Typeflag: tar.TypeReg, Size: 2, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "dangle", Typeflag: tar.TypeSymlink, Linkname: "missing/no.txt", Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.resolvedSymlinkTargetForPatterns("dangle", "missing/no.txt"); got != "" {
		t.Fatalf("dangling relative: got %q want empty", got)
	}
	if idx.resolvedTargetHasIndexedSubtree("missing") {
		t.Fatal("missing should not name indexed content")
	}
}

func TestResolvedSymlinkTargetForPatternsDanglingAbsolute(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "real.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "absdangle", Typeflag: tar.TypeSymlink, Linkname: "/not/in/tar", Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	idx, err := buildLinkIndex(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.resolvedSymlinkTargetForPatterns("absdangle", "/not/in/tar"); got != "" {
		t.Fatalf("dangling absolute: got %q want empty", got)
	}
}

func TestUntarDanglingSymlinkDoesNotFail(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "keep.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "dangle", Typeflag: tar.TypeSymlink, Linkname: "ghost/missing.txt", Mode: 0o777, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	img, err := createImageWithLayer(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := untar(context.Background(), tmpDir, img, []string{"keep.txt", "dangle"}); err != nil {
		t.Fatalf("untar: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(tmpDir, "keep.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(tmpDir, "dangle")); err != nil {
		t.Fatalf("dangle symlink: %v", err)
	}
}
