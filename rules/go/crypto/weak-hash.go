package digest

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	legacymd5 "crypto/md5"
	simdmd5 "example.com/simd/md5"
	"golang.org/x/crypto/sha3"
)

// crypto/md5: "MD5 is cryptographically broken and should not be used for secure applications."
func PasswordDigest(password, salt string) string {
	// ruleid: go.weak-hash
	sum := md5.Sum([]byte(salt + password))
	return hex.EncodeToString(sum[:])
}

func FileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// A checksum is still a use of MD5: the hotspot asks a person to confirm it is not security.
	// ruleid: go.weak-hash
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// crypto/sha1: "SHA-1 is cryptographically broken and should not be used for secure applications."
func TokenID(token []byte) string {
	// ruleid: go.weak-hash
	return fmt.Sprintf("%x", sha1.Sum(token))
}

func ObjectID(kind string, body []byte) []byte {
	// A git object id is SHA-1 by the format's definition: reported, for a person to confirm.
	// ruleid: go.weak-hash
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(body))
	h.Write(body)
	return h.Sum(nil)
}

// The same functions in other positions and through the crypto.Hash registry.
func Positions(data []byte) {
	// ruleid: go.weak-hash
	io.WriteString(md5.New(), "x")
	// ruleid: go.weak-hash
	key := hex.EncodeToString(func() []byte { s := sha1.Sum(data); return s[:] }())
	_ = key
	// ruleid: go.weak-hash
	hm := crypto.MD5.New()
	_ = hm
	// ruleid: go.weak-hash
	hs := crypto.SHA1.New()
	_ = hs
	// The package imported under another name.
	// ruleid: go.weak-hash
	legacymd5.Sum(data)
	if crypto.SHA1.Available() {
		// ruleid: go.weak-hash
		crypto.SHA1.New().Write(data)
	}
}

// SHA-2 and SHA-3: the hashes to use instead.
func Strong(data []byte) {
	// ok: go.weak-hash
	a := sha256.Sum256(data)
	_ = a
	// ok: go.weak-hash
	h := sha256.New()
	h.Write(data)
	// ok: go.weak-hash
	b := sha512.Sum512(data)
	_ = b
	// ok: go.weak-hash
	h5 := sha512.New()
	_ = h5
	// ok: go.weak-hash
	c := sha3.Sum256(data)
	_ = c
	// ok: go.weak-hash
	h3 := crypto.SHA256.New()
	_ = h3
}

// Not a hash computed here: the packages' constants, SHA-256 handed to HMAC, and methods of
// the same name elsewhere.
type store struct{}

func (store) Sum(b []byte) []byte { return b }
func (store) New() store          { return store{} }

func NotWeakUses(key, data []byte, s store) {
	// ok: go.weak-hash
	buf := make([]byte, md5.Size)
	_ = buf
	// ok: go.weak-hash
	_ = sha1.BlockSize
	// ok: go.weak-hash
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	// ok: go.weak-hash
	_ = s.Sum(data)
	// ok: go.weak-hash
	_ = s.New()
	// ok: go.weak-hash
	fmt.Println(crypto.SHA1.String())
}

// Known limits.
func limits(key, data []byte) {
	// A function value handed to HMAC or a KDF is not followed (only calls of New and Sum are).
	// todoruleid: go.weak-hash
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	// A package of another path whose last element is also md5, imported under an alias next
	// to crypto/md5, is taken for crypto/md5.
	// todook: go.weak-hash
	simdmd5.Sum(data)
	// A local variable that shadows the package name is taken for the package.
	{
		md5 := store{}
		// todook: go.weak-hash
		md5.Sum(data)
	}
}
