package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/app/mail"
)

const skipVerify = true

// InsecureSkipVerify in a literal: http.Transport, tls.Dial, tls.Client, tls.Dialer.
func Clients(addr string, conn net.Conn) {
	_ = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// ruleid: go.tls-verification-disabled
				InsecureSkipVerify: true,
			},
		},
	}
	// ruleid: go.tls-verification-disabled
	c, _ := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	c.Close()
	// ruleid: go.tls-verification-disabled
	tls.Client(conn, &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true})
	// ruleid: go.tls-verification-disabled
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	d.Dial("tcp", addr)
	// ruleid: go.tls-verification-disabled
	cfg := tls.Config{InsecureSkipVerify: true}
	tls.DialWithDialer(&net.Dialer{}, "tcp", addr, &cfg)
	// A constant set to true.
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: skipVerify})
}

// The field set after the config is made.
func Assigned(addr string, base *tls.Config) *http.Transport {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	// ruleid: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	tls.Dial("tcp", addr, cfg)
	clone := base.Clone()
	// ruleid: go.tls-verification-disabled
	base.InsecureSkipVerify = true
	_ = clone
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// ruleid: go.tls-verification-disabled
	tr.TLSClientConfig.InsecureSkipVerify = true
	conf := new(tls.Config)
	// ruleid: go.tls-verification-disabled
	conf.InsecureSkipVerify = true
	var plain tls.Config
	// ruleid: go.tls-verification-disabled
	plain.InsecureSkipVerify = true
	return &http.Transport{TLSClientConfig: conf}
}

// Verification kept on.
func Verified(addr string, pool *x509.CertPool, insecure bool) {
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: false})
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "db.internal"})
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	// ok: go.tls-verification-disabled
	cfg.InsecureSkipVerify = false
	// ok: go.tls-verification-disabled
	_ = &http.Transport{TLSClientConfig: &tls.Config{}}
	// A switch the operator sets (an option or a flag), not a fixed choice of the program.
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: insecure})
}

// The crypto/tls docs: InsecureSkipVerify "should be used only for testing or in combination
// with VerifyConnection or VerifyPeerCertificate".
func CustomVerification(addr string, pool *x509.CertPool, pin []byte) {
	verify := func(cs tls.ConnectionState) error {
		opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: verify})
	tls.Dial("tcp", addr, &tls.Config{
		// ok: go.tls-verification-disabled
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if !bytes.Equal(sum[:], pin) {
				return errors.New("certificate does not match the pin")
			}
			return nil
		},
	})
	cfg := &tls.Config{}
	// ok: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = verify
	tls.Dial("tcp", addr, cfg)
}

// A callback whose body is only `return nil` checks nothing: with InsecureSkipVerify its
// verifiedChains are nil, so it accepts every certificate.
func EmptyCallbacks(addr string) {
	trustAll := &tls.Config{
		// ruleid: go.tls-verification-disabled
		InsecureSkipVerify: true,
	}
	trustAll.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error { return nil }
	tls.Dial("tcp", addr, trustAll)
	tls.Dial("tcp", addr, &tls.Config{
		// ruleid: go.tls-verification-disabled
		InsecureSkipVerify: true,
		VerifyConnection: func(tls.ConnectionState) error {
			return nil
		},
	})
	cfg := new(tls.Config)
	// ruleid: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error { return nil }
	tls.Dial("tcp", addr, cfg)
}

// The same empty callback held in a variable, a package variable or a named function.
var trustEveryone = func(tls.ConnectionState) error { return nil }

func acceptEverything(tls.ConnectionState) error { return nil }

func NoopCallbacks(addr string) {
	noop := func(cs tls.ConnectionState) error { return nil }
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: noop})
	var acceptAll = func(raw [][]byte, _ [][]*x509.Certificate) error { return nil }
	tls.Dial("tcp", addr, &tls.Config{
		// ruleid: go.tls-verification-disabled
		InsecureSkipVerify: true,
		VerifyPeerCertificate: acceptAll,
	})
	cfg := &tls.Config{}
	// ruleid: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = noop
	tls.Dial("tcp", addr, cfg)
	other := tls.Config{}
	other.VerifyPeerCertificate = acceptAll
	// ruleid: go.tls-verification-disabled
	other.InsecureSkipVerify = true
	built := &tls.Config{
		// ruleid: go.tls-verification-disabled
		InsecureSkipVerify: true,
	}
	built.VerifyConnection = noop
	tls.Dial("tcp", addr, built)
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: trustEveryone})
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: acceptEverything})
	viaFunc := &tls.Config{}
	viaFunc.VerifyConnection = acceptEverything
	// ruleid: go.tls-verification-disabled
	viaFunc.InsecureSkipVerify = true
	// Declared further down the file.
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: skipChainCheck})
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: allowAnyPeer})
}

type pool struct{ addr string }

func (p *pool) dial() (*tls.Conn, error) {
	cfg := &tls.Config{}
	cfg.VerifyConnection = allowAnyPeer
	// ruleid: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	return tls.Dial("tcp", p.addr, cfg)
}

func skipChainCheck(raw [][]byte, chains [][]*x509.Certificate) error { return nil }

var allowAnyPeer = func(tls.ConnectionState) error { return nil }

// Callbacks held in variables or named functions that do check the certificate.
func checkLeaf(pool *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool})
		return err
	}
}

func verifyAgainstSystem(cs tls.ConnectionState) error {
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: cs.ServerName})
	return err
}

func CheckingCallbacks(addr string, pool *x509.CertPool) {
	noop := checkLeaf(pool)
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: noop})
	cfg := &tls.Config{}
	// ok: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = verifyAgainstSystem
	tls.Dial("tcp", addr, cfg)
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: verifyAgainstSystem})
	// An empty callback assigned to a variable of another name is not the one in use.
	unused := func(tls.ConnectionState) error { return nil }
	_ = unused
	// ok: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: verifyAgainstSystem})
}

// Tests: an httptest TLS server has a self-signed certificate; the docs allow skipping
// verification for testing. Test functions and functions that start such a server are left out
// (and *_test.go files are excluded by the rule's paths).
func TestFetch(t *testing.T) {
	// ok: go.tls-verification-disabled
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	_ = tr
}

func BenchmarkFetch(b *testing.B) {
	cfg := &tls.Config{}
	// ok: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	_ = cfg
}

func fetchHelper(tb testing.TB, url string) {
	// ok: go.tls-verification-disabled
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	c.Get(url)
}

func newTestServerClient(h http.Handler) (*httptest.Server, *http.Client) {
	srv := httptest.NewTLSServer(h)
	// ok: go.tls-verification-disabled
	return srv, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func newUnstarted(h http.Handler) *http.Client {
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	cfg := &tls.Config{}
	// ok: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

// A test server given as a parameter and started here.
func startedHere(srv *httptest.Server) *http.Client {
	srv.StartTLS()
	// ok: go.tls-verification-disabled
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

// StartTLS of another type (a mail or database connection) is not a test server.
type smtpConn struct{}

func (smtpConn) StartTLS() error { return nil }

func upgrade(addr string, c smtpConn) {
	c.StartTLS()
	// ruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
}

// The client a test server gives is the documented way: it trusts the server's certificate.
func serverClient(h http.Handler) *http.Client {
	srv := httptest.NewTLSServer(h)
	// ok: go.tls-verification-disabled
	return srv.Client()
}

// Look-alikes: an option of the same name on another library's or the program's own types.
type Options struct {
	InsecureSkipVerify bool
}

func LookAlikes(o *Options) {
	// ok: go.tls-verification-disabled
	_ = Options{InsecureSkipVerify: true}
	// ok: go.tls-verification-disabled
	o.InsecureSkipVerify = true
	// ok: go.tls-verification-disabled
	_ = mail.Config{Host: "smtp.example.com", InsecureSkipVerify: true}
}

// Known limits.
func limits(addr string, base tls.Config) {
	// A config returned by a function (of this file or another) and changed here has no type
	// to bind to.
	cfg := makeConfig()
	// todoruleid: go.tls-verification-disabled
	cfg.InsecureSkipVerify = true
	cfg2 := sameFileConfig()
	// todoruleid: go.tls-verification-disabled
	cfg2.InsecureSkipVerify = true
	// A variable that held an empty callback and was then given a real one still counts as
	// empty.
	check := func(tls.ConnectionState) error { return nil }
	check = verifyAgainstSystem
	// todook: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: check})
	// An empty method used as the callback is not followed.
	// todoruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, VerifyConnection: trustingPeer{}.Check})
	// A function-local variable set to true is not a constant.
	skip := true
	// todoruleid: go.tls-verification-disabled
	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: skip})
}

func sameFileConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }

type trustingPeer struct{}

func (trustingPeer) Check(tls.ConnectionState) error { return nil }
