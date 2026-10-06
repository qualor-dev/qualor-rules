package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	legacydes "crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"io"
	"slices"

	vendorrc4 "example.com/legacy/rc4"
	"golang.org/x/crypto/chacha20poly1305"
)

// crypto/des: "DES is cryptographically broken and should not be used for secure applications."
func SealDES(key, iv, plaintext []byte) []byte {
	// ruleid: go.weak-cipher
	block, err := des.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

// Triple DES (TDEA) lives in the same package and carries the same warning.
func Seal3DES(key, iv, plaintext []byte) []byte {
	// ruleid: go.weak-cipher
	block, _ := des.NewTripleDESCipher(key)
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

// crypto/rc4: "RC4 is cryptographically broken and should not be used for secure applications."
func StreamRC4(key, data []byte) []byte {
	// ruleid: go.weak-cipher
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// Package-level function values.
var (
	// ruleid: go.weak-cipher
	legacyBlock = des.NewCipher
	// ruleid: go.weak-cipher
	legacyStream = rc4.NewCipher
	// ok: go.weak-cipher
	modernBlock = aes.NewCipher
)

// The calls in other positions: returned, passed on, used in place, in a function value.
type legacy struct {
	newBlock func([]byte) (cipher.Block, error)
}

func Positions(key []byte) (cipher.Block, error) {
	// ruleid: go.weak-cipher
	_, _ = cipher.NewGCM(must(des.NewCipher(key)))
	// ruleid: go.weak-cipher
	stream := cipher.NewCTR(must(des.NewTripleDESCipher(key)), make([]byte, des.BlockSize))
	_ = stream
	// ruleid: go.weak-cipher
	if c, err := rc4.NewCipher(key); err == nil {
		c.Reset()
	}
	// A function value is a use too.
	// ruleid: go.weak-cipher
	_ = legacy{newBlock: des.NewCipher}
	// The package imported under another name.
	// ruleid: go.weak-cipher
	legacydes.NewCipher(key)
	// ruleid: go.weak-cipher
	return des.NewTripleDESCipher(key)
}

func must(b cipher.Block, err error) cipher.Block {
	if err != nil {
		panic(err)
	}
	return b
}

// AES-GCM and ChaCha20-Poly1305: the authenticated ciphers the Go docs point to.
func SealAESGCM(key, plaintext []byte) ([]byte, error) {
	// ok: go.weak-cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// ok: go.weak-cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// ok: go.weak-cipher
	if _, err := cipher.NewGCMWithRandomNonce(block); err != nil {
		return nil, err
	}
	// ok: go.weak-cipher
	_ = cipher.NewCTR(block, make([]byte, aes.BlockSize))
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func SealChaCha(key, plaintext []byte) ([]byte, error) {
	// ok: go.weak-cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	// ok: go.weak-cipher
	x, _ := chacha20poly1305.NewX(key)
	_ = x
	nonce := make([]byte, aead.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Look-alikes: the packages' constants, and NewCipher of other packages and types.
type myCipher struct{}

func (myCipher) NewCipher(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }

func LookAlikes(key []byte, m myCipher) {
	// ok: go.weak-cipher
	size := des.BlockSize
	_ = size
	// ok: go.weak-cipher
	m.NewCipher(key)
	// ok: go.weak-cipher
	_ = rc4.KeySizeError(3)
}

// Known limits.
func limits() *tls.Config {
	// A package of another path whose last element is also rc4, imported under an alias next
	// to crypto/rc4, is taken for crypto/rc4.
	// todook: go.weak-cipher
	vendorrc4.NewCipher(nil)
	// A local variable that shadows the package name.
	{
		des := myCipher{}
		// todook: go.weak-cipher
		des.NewCipher(nil)
	}
	// The TLS 1.0-1.2 cipher suites with RC4 or 3DES (crypto/tls InsecureCipherSuites).
	return &tls.Config{
		// ruleid: go.weak-cipher
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	}
}

// crypto/tls: the cipher suites InsecureCipherSuites lists ("have security issues"; RC4, 3DES,
// RSA key exchange, CBC with SHA-256), enabled in a tls.Config.
func LegacyServer() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			// ok: go.weak-cipher
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// ruleid: go.weak-cipher
			tls.TLS_RSA_WITH_RC4_128_SHA,
			// ruleid: go.weak-cipher
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			// ruleid: go.weak-cipher
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			// ruleid: go.weak-cipher
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			// ruleid: go.weak-cipher
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// ruleid: go.weak-cipher
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			// ruleid: go.weak-cipher
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			// ruleid: go.weak-cipher
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// ruleid: go.weak-cipher
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			// ruleid: go.weak-cipher
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	}
}

// The suites set on a config built first, appended to its list, or held in a variable.
var compatSuites = []uint16{
	// ruleid: go.weak-cipher
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	// ok: go.weak-cipher
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
}

func ClientConfig(legacy bool) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// ok: go.weak-cipher
	disabled := tls.CipherSuiteName(tls.TLS_RSA_WITH_RC4_128_SHA)
	_ = disabled
	// ruleid: go.weak-cipher
	cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
	if legacy {
		// ruleid: go.weak-cipher
		cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)
	}
	suites := []uint16{
		// ruleid: go.weak-cipher
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}
	// A suite named outside the list, between the list and its use.
	// ok: go.weak-cipher
	if suites[0] == tls.TLS_RSA_WITH_AES_256_CBC_SHA {
		return nil
	}
	other := &tls.Config{CipherSuites: suites}
	_ = other
	return &tls.Config{CipherSuites: compatSuites}
}

// A list variable assigned to the field, declared with var, or spread into an append.
var fallbackSuites = []uint16{
	// ruleid: go.weak-cipher
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
}

func Fallback(cfg *tls.Config) {
	cfg.CipherSuites = fallbackSuites
	var local = []uint16{
		// ruleid: go.weak-cipher
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	cfg.CipherSuites = local
	extra := []uint16{
		// ruleid: go.weak-cipher
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		// ok: go.weak-cipher
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	cfg.CipherSuites = append(cfg.CipherSuites, extra...)
}

// A deny-list handed to a filter names the suites it removes.
var refused = []uint16{
	// ok: go.weak-cipher
	tls.TLS_RSA_WITH_RC4_128_SHA,
}

func dropSuites(all, drop []uint16) []uint16 {
	var kept []uint16
	for _, id := range all {
		if !slices.Contains(drop, id) {
			kept = append(kept, id)
		}
	}
	return kept
}

func Hardened(cfg *tls.Config, defaults []uint16) *tls.Config {
	blocked := []uint16{
		// ok: go.weak-cipher
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	cfg.CipherSuites = dropSuites(defaults, blocked)
	return &tls.Config{CipherSuites: dropSuites(defaults, refused)}
}

// The safe forms: the suites CipherSuites lists, the default list, TLS 1.3 only, and the
// constants used outside a tls.Config (a name for a log line, a comparison).
func ModernServer() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			// ok: go.weak-cipher
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// ok: go.weak-cipher
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			// ok: go.weak-cipher
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
	}
}

func DefaultSuites() *tls.Config {
	// ok: go.weak-cipher
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func DescribeSuite(state tls.ConnectionState) string {
	// ok: go.weak-cipher
	if state.CipherSuite == tls.TLS_RSA_WITH_RC4_128_SHA {
		return "legacy"
	}
	switch state.CipherSuite {
	// ok: go.weak-cipher
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "legacy"
	}
	// ok: go.weak-cipher
	return tls.CipherSuiteName(tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
}

// Not followed: suite IDs written as numbers, and the whole insecure list enabled in a loop.
func NumericSuites() *tls.Config {
	ids := []uint16{}
	for _, s := range tls.InsecureCipherSuites() {
		// todoruleid: go.weak-cipher
		ids = append(ids, s.ID)
	}
	_ = &tls.Config{CipherSuites: ids}
	return &tls.Config{
		// todoruleid: go.weak-cipher
		CipherSuites: []uint16{0x0005, 0x000a},
	}
}
