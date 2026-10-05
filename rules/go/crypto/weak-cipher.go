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
	// The TLS 1.0-1.2 cipher suites with RC4 or 3DES (crypto/tls InsecureCipherSuites) are not
	// followed.
	return &tls.Config{
		// todoruleid: go.weak-cipher
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	}
}
