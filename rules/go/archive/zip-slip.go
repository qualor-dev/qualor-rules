package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var errUnsafe = errors.New("unsafe entry name")

// archive/zip: the name of each entry comes from the archive, which may hold "../" or an
// absolute name (the reader accepts them unless GODEBUG zipinsecurepath=0 is set).
func Unzip(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		target := filepath.Join(dst, f.Name)
		if f.FileInfo().IsDir() {
			// ruleid: go.zip-slip
			os.MkdirAll(target, 0o755)
			continue
		}
		// ruleid: go.zip-slip
		os.MkdirAll(filepath.Dir(target), 0o755)
		// ruleid: go.zip-slip
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, _ := f.Open()
		io.Copy(out, rc)
		rc.Close()
		out.Close()
	}
	return nil
}

// A *zip.Reader made from bytes, entries reached by index, and the name used in place.
func UnzipBytes(data []byte, dst string) {
	zr, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	for i := range zr.File {
		// ruleid: go.zip-slip
		os.Create(dst + "/" + zr.File[i].Name)
	}
	for _, f := range zr.File {
		// ruleid: go.zip-slip
		os.WriteFile(fmt.Sprintf("%s/%s", dst, f.Name), nil, 0o644)
		name := f.FileHeader.Name
		// ruleid: go.zip-slip
		ioutil.WriteFile(filepath.Join(dst, name), nil, 0o644)
		// ruleid: go.zip-slip
		os.Mkdir(filepath.Join(dst, name), 0o755)
	}
}

// A helper given the reader or one entry: the parameter's type says it is an archive.
func extractAll(zr *zip.Reader, dst string) {
	for _, f := range zr.File {
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
}

func extractOne(rc *zip.ReadCloser, f *zip.File, h *zip.FileHeader, dst string) {
	// ruleid: go.zip-slip
	os.Create(filepath.Join(dst, f.Name))
	// ruleid: go.zip-slip
	os.Create(filepath.Join(dst, h.Name))
	for _, e := range rc.File {
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, e.Name))
	}
}

// archive/tar: Header.Name, and Header.Linkname for links (the tar docs: only file names are
// checked by tarinsecurepath, never link targets).
func Untar(in io.Reader, dst string) error {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			// ruleid: go.zip-slip
			os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			// ruleid: go.zip-slip
			out, _ := os.Create(target)
			io.Copy(out, tr)
			out.Close()
		case tar.TypeSymlink:
			// ruleid: go.zip-slip
			os.Symlink(hdr.Linkname, filepath.Join(dst, filepath.Base(hdr.Name)))
		case tar.TypeLink:
			// ruleid: go.zip-slip
			os.Link(filepath.Join(dst, hdr.Linkname), filepath.Join(dst, filepath.Base(hdr.Name)))
		}
	}
}

func untarEntry(tr *tar.Reader, h *tar.Header, dst string) {
	// ruleid: go.zip-slip
	os.Create(filepath.Join(dst, h.Name))
	var hdr *tar.Header
	hdr, _ = tr.Next()
	// ruleid: go.zip-slip
	os.Create(filepath.Join(dst, hdr.Name))
}

// Checks that do not keep the name inside the directory.
func weakChecks(zr *zip.Reader, dst string) {
	for _, f := range zr.File {
		// Clean keeps leading ".." elements of a relative name.
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, filepath.Clean(f.Name)))
		// Removing "../" once leaves "../" in "....//" (CWE-22).
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, strings.ReplaceAll(f.Name, "../", "")))
		// The check only warns: the entry is still written.
		if !filepath.IsLocal(f.Name) {
			fmt.Println("warning: non-local name", f.Name)
		}
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if filepath.IsLocal(f.Name) {
			fmt.Println("local:", f.Name)
		}
		// Outside the checked branch.
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
}

// Checks that leave only on some paths, and the branch where the check failed.
func partialChecks(zr *zip.Reader, dst string, lenient bool) error {
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			if !lenient {
				return errUnsafe
			}
			fmt.Println("writing a non-local name:", f.Name)
		}
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			// The continue leaves the inner loop only.
			for _, sep := range []string{"/", "\\"} {
				if strings.HasPrefix(f.Name, sep) {
					continue
				}
			}
		}
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if filepath.IsLocal(f.Name) {
			fmt.Println("local:", f.Name)
		} else {
			// ruleid: go.zip-slip
			os.Create(filepath.Join(dst, f.Name))
		}
	}
	return nil
}

// filepath.IsLocal: the check the archive/zip and archive/tar docs name for insecure paths.
func checked(zr *zip.Reader, tr *tar.Reader, dst string) error {
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			return errUnsafe
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		name := f.Name
		if !filepath.IsLocal(name) {
			continue
		}
		// ok: go.zip-slip
		os.MkdirAll(filepath.Join(dst, name), 0o755)
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			fmt.Println("skipping", f.Name)
			continue
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if filepath.IsLocal(f.Name) {
			// ok: go.zip-slip
			os.WriteFile(filepath.Join(dst, f.Name), nil, 0o644)
		}
	}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if !filepath.IsLocal(hdr.Name) {
			return errUnsafe
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, hdr.Name))
	}
	return nil
}

// Guards that end the program (log.Fatal*, os.Exit), panic through log.Panic*, or leave the loop
// by its label.
func exits(zr *zip.Reader, dst string, logger *log.Logger) {
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			log.Fatal("unsafe entry name")
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			log.Fatalf("unsafe entry name %q", f.Name)
		}
		// ok: go.zip-slip
		os.MkdirAll(filepath.Join(dst, f.Name), 0o755)
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			fmt.Println("refusing the archive")
			log.Fatalln("unsafe entry name", f.Name)
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			log.Panicf("unsafe entry name %q", f.Name)
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			fmt.Println("unsafe entry name", f.Name)
			os.Exit(2)
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			logger.Fatalf("unsafe entry name %q", f.Name)
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
entries:
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			continue entries
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
names:
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			fmt.Println("stopping at", f.Name)
			break names
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	// Logging alone does not leave the loop.
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			log.Printf("unsafe entry name %q", f.Name)
		}
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			logger.Println("unsafe entry name", f.Name)
		}
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
}

// filepath.Localize returns a local path or an error; filepath.Base and FileInfo().Name() keep
// only the last element of the name.
func localized(zr *zip.Reader, dst string) {
	for _, f := range zr.File {
		local, err := filepath.Localize(f.Name)
		if err != nil {
			continue
		}
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, local))
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, filepath.Base(f.Name)))
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.FileInfo().Name()))
	}
}

// os.Root (Go 1.24) refuses names that leave the directory, through ".." or a symbolic link.
func rooted(zr *zip.Reader, tr *tar.Reader, dst string) error {
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range zr.File {
		// ok: go.zip-slip
		root.MkdirAll(path.Dir(f.Name), 0o755)
		// ok: go.zip-slip
		out, err := root.Create(f.Name)
		if err != nil {
			return err
		}
		out.Close()
		// ok: go.zip-slip
		root.OpenFile(f.Name, os.O_WRONLY|os.O_CREATE, 0o644)
		// ok: go.zip-slip
		os.OpenInRoot(dst, f.Name)
	}
	hdr, _ := tr.Next()
	// ok: go.zip-slip
	root.Create(hdr.Name)
	return nil
}

// Not an archive entry: names from constants, from the program, from other structs named File.
type upload struct {
	File []struct{ Name string }
}

func notArchive(u upload, dst string) {
	// ok: go.zip-slip
	os.Create(filepath.Join(dst, "manifest.json"))
	for _, f := range u.File {
		// ok: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	// Writing an archive: the names are the program's own.
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	w, _ := zw.Create("report.txt")
	w.Write([]byte("x"))
	zw.Close()
	// ok: go.zip-slip
	os.WriteFile(filepath.Join(dst, "report.zip"), buf.Bytes(), 0o644)
	// The fs.FS view of a zip.Reader has no leading "/" or "../" elements (Reader.Open).
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	// ok: go.zip-slip
	os.CopyFS(dst, zr)
	// Reading the entry's data is not a file path.
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		// ok: go.zip-slip
		os.WriteFile(filepath.Join(dst, "blob.bin"), data, 0o644)
	}
}

// Known limits.
func limits(zr *zip.Reader, dst string) error {
	for _, f := range zr.File {
		target := filepath.Join(dst, f.Name)
		// A prefix check on the joined path is not followed (no official doc describes it; a
		// prefix without a trailing separator also lets "dst-evil/x" through).
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(os.PathSeparator)) {
			return errUnsafe
		}
		// todook: go.zip-slip
		os.Create(target)
	}
	for _, f := range zr.File {
		// path.Base splits on "/" only: safe on Unix, not for a "..\\" name on Windows.
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, path.Base(f.Name)))
		// Clean of a rooted name drops its leading ".." elements.
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, filepath.Clean("/"+f.Name)))
	}
	for _, f := range zr.File {
		// The true branch of an if with an else is not followed.
		if filepath.IsLocal(f.Name) {
			// todook: go.zip-slip
			os.Create(filepath.Join(dst, f.Name))
		} else {
			fmt.Println("skipping", f.Name)
		}
		// The check in the if's init statement is not followed.
		if ok := filepath.IsLocal(f.Name); !ok {
			continue
		}
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		// A guard whose body has more than three statements is not followed.
		if !filepath.IsLocal(f.Name) {
			fmt.Println("skipping")
			fmt.Println(f.Name)
			fmt.Println(f.Comment)
			continue
		}
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		// Ad hoc string checks are not followed (no official doc describes them; ".." alone does
		// not cover an absolute name used without a join).
		if strings.Contains(f.Name, "..") {
			continue
		}
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		// A check joined with other conditions is not followed.
		if !filepath.IsLocal(f.Name) || strings.HasPrefix(f.Name, ".") {
			continue
		}
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		// A *log.Logger the rule cannot type (from log.New or log.Default in a := declaration) is
		// not taken as exiting.
		std := log.Default()
		if !filepath.IsLocal(f.Name) {
			std.Fatal("unsafe entry name")
		}
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	for _, f := range zr.File {
		// A deferred exit runs only when the function returns, after the file is created, but the
		// rule takes it as an exit.
		if !filepath.IsLocal(f.Name) {
			defer os.Exit(1)
		}
		// todoruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	// zip.OpenReader returns ErrInsecurePath only with GODEBUG zipinsecurepath=0 (a //go:debug
	// line or go.mod); the rule cannot see that setting, so the entries stay reported.
	r, err := zip.OpenReader("in.zip")
	if errors.Is(err, zip.ErrInsecurePath) {
		return err
	}
	for _, f := range r.File {
		// todook: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
		// Metadata calls on the path are not sinks; the file's creation is reported.
		// todoruleid: go.zip-slip
		os.Chmod(filepath.Join(dst, f.Name), f.Mode())
	}
	// A slice of entries copied out of the reader is still the archive's.
	files := r.File
	for _, f := range files {
		// ruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
	return nil
}

// A value named log that is not the log package: its Fatal is taken as an exit by its name.
type auditTrail struct{ lines []string }

func (a *auditTrail) Fatal(v ...any) { a.lines = append(a.lines, fmt.Sprint(v...)) }

func shadowedLog(zr *zip.Reader, dst string, log *auditTrail) {
	for _, f := range zr.File {
		if !filepath.IsLocal(f.Name) {
			log.Fatal("unsafe entry name")
		}
		// todoruleid: go.zip-slip
		os.Create(filepath.Join(dst, f.Name))
	}
}
