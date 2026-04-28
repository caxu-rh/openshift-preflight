package engine

import (
	"bytes"
	"testing"
)

func TestComputeNeededLinkMembersMatchesLinkHeaderNeeded(t *testing.T) {
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
	needed := idx.computeNeededLinkMembers(patterns)

	for ln := range idx.linkMemberNames {
		want := idx.linkHeaderNeeded(ln, patterns)
		_, got := needed[ln]
		if want != got {
			t.Fatalf("link %q: linkHeaderNeeded=%v computeNeeded=%v", ln, want, got)
		}
	}
}
