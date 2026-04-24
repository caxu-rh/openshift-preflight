package container

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/redhat-openshift-ecosystem/openshift-preflight/internal/image"
)

const (
	emptyLicense = "emptylicense.txt"
	validLicense = "mylicense.txt"
	licenses     = "licenses"
)

func setupTmpDir() string {
	tmpDir, err := os.MkdirTemp("", "license-check-*")
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		os.RemoveAll(tmpDir)
	})
	return tmpDir
}

func createLicenseDir(tmpDir string) {
	err := os.Mkdir(filepath.Join(tmpDir, licenses), 0o755)
	Expect(err).ToNot(HaveOccurred())
}

func createLicenseFile(tmpDir, path string) {
	fullPath := filepath.Join(tmpDir, licenses, path)
	err := os.MkdirAll(filepath.Dir(fullPath), 0o755)
	Expect(err).ToNot(HaveOccurred())
	err = os.WriteFile(fullPath, []byte("This is a license"), 0o644)
	Expect(err).ToNot(HaveOccurred())
}

func createEmptyFile(tmpDir, path string) {
	fullPath := filepath.Join(tmpDir, licenses, path)
	_, err := os.Create(fullPath)
	Expect(err).ToNot(HaveOccurred())
}

var _ = Describe("HasLicense", func() {
	var hasLicense HasLicenseCheck

	Describe("Checking if licenses can be found", func() {
		Context("When license(s) are found at top level", func() {
			It("Should pass Validate", func() {
				tmpDir := setupTmpDir()
				createLicenseDir(tmpDir)
				createLicenseFile(tmpDir, validLicense)
				createEmptyFile(tmpDir, emptyLicense)

				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: tmpDir})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeTrue())
			})
		})

		Context("When licenses directory is not found", func() {
			It("Should not pass Validate", func() {
				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: "/invalid"})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeFalse())
			})
		})

		// This shouldn't happen in practice, since the untar extraction
		// logic will prune/not create empty directories.
		Context("When licenses directory exists but is empty", func() {
			It("Should not pass Validate", func() {
				tmpDir := setupTmpDir()
				createLicenseDir(tmpDir)

				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: tmpDir})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeFalse())
			})
		})

		Context("When only an empty license file exists", func() {
			It("Should not pass Validate", func() {
				tmpDir := setupTmpDir()
				createLicenseDir(tmpDir)
				createEmptyFile(tmpDir, emptyLicense)

				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: tmpDir})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeFalse())
			})
		})

		// This shouldn't happen in practice, since the untar extraction
		// logic will prune/not create empty directories.
		Context("When only directories exist in the license folder", func() {
			It("Should not pass Validate", func() {
				tmpDir := setupTmpDir()
				createLicenseDir(tmpDir)
				err := os.MkdirAll(filepath.Join(tmpDir, licenses, "just-another-dir"), 0o755)
				Expect(err).ToNot(HaveOccurred())

				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: tmpDir})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeFalse())
			})
		})

		Context("When license is found only in nested subdirectory", func() {
			It("Should pass Validate", func() {
				tmpDir := setupTmpDir()
				createLicenseDir(tmpDir)
				createLicenseFile(tmpDir, filepath.Join("a/b/c", validLicense))

				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: tmpDir})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeTrue())
			})
		})

		Context("When /licenses is a symlink to a directory that contains license files", func() {
			It("Should pass Validate and count each regular file, not the symlink alone", func() {
				if runtime.GOOS == "windows" {
					Skip("symlink fixture not portable on Windows")
				}
				tmpDir := setupTmpDir()
				targetDir := filepath.Join(tmpDir, "licenses-target")
				Expect(os.Mkdir(targetDir, 0o755)).To(Succeed())
				licenseNames := []string{validLicense, "second-license.txt", "third-license.txt"}
				for _, name := range licenseNames {
					Expect(os.WriteFile(filepath.Join(targetDir, name), []byte("This is a license"), 0o644)).To(Succeed())
				}
				Expect(os.Symlink(targetDir, filepath.Join(tmpDir, licenses))).To(Succeed())

				entries, err := hasLicense.getDataToValidate(context.TODO(), tmpDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(entries).To(HaveLen(len(licenseNames)), "buggy walk counted the /licenses symlink as one file instead of walking the target directory")

				ok, err := hasLicense.Validate(context.TODO(), image.ImageReference{ImageFSPath: tmpDir})
				Expect(err).ToNot(HaveOccurred())
				Expect(ok).To(BeTrue())
			})
		})

		AssertMetaData(&hasLicense)
	})
})
