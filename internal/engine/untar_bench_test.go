package engine

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func writeBenchTar(w io.Writer, nReg, nSym int) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	for i := range nReg {
		name := fmt.Sprintf("files/%d/blob", i)
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Typeflag: tar.TypeReg,
			Size:     64,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(bytes.Repeat([]byte{byte(i % 255)}, 64)); err != nil {
			return err
		}
	}
	for i := range nSym {
		target := fmt.Sprintf("/files/%d/blob", i%nReg)
		hdr := &tar.Header{
			Name:     fmt.Sprintf("links/%d/sym", i),
			Mode:     0o777,
			Typeflag: tar.TypeSymlink,
			Linkname: target,
			Size:     0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
	}
	return nil
}

func benchImage(b *testing.B, nReg, nSym int) v1.Image {
	b.Helper()
	var buf bytes.Buffer
	if err := writeBenchTar(&buf, nReg, nSym); err != nil {
		b.Fatal(err)
	}
	layer := static.NewLayer(buf.Bytes(), types.DockerLayer)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		b.Fatal(err)
	}
	return img
}

func BenchmarkBuildLinkIndex_10kRegs_2kSyms(b *testing.B) {
	img := benchImage(b, 10000, 2000)
	b.ResetTimer()
	for b.Loop() {
		r := mutate.Extract(img)
		_, err := buildLinkIndex(r)
		_ = r.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeNeededLinkMembers_10kRegs_2kSyms(b *testing.B) {
	img := benchImage(b, 10000, 2000)
	r := mutate.Extract(img)
	idx, err := buildLinkIndex(r)
	_ = r.Close()
	if err != nil {
		b.Fatal(err)
	}
	patterns := expandLiteralPatternsWithDescendantGlob([]string{"files/**/blob"})
	b.ResetTimer()
	for b.Loop() {
		_ = idx.computeNeededLinkMembers(patterns)
	}
}

func BenchmarkMemberMatchesPatterns_10kRegs(b *testing.B) {
	img := benchImage(b, 10000, 2000)
	r := mutate.Extract(img)
	idx, err := buildLinkIndex(r)
	_ = r.Close()
	if err != nil {
		b.Fatal(err)
	}
	patterns := expandLiteralPatternsWithDescendantGlob([]string{"files/**/blob"})
	name := "files/5000/blob"
	b.ResetTimer()
	for b.Loop() {
		_ = idx.memberMatchesPatterns(name, patterns)
	}
}
