package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hinoobers/noobtunnel-agent/internal/tlsutil"
)

func TestInstallRequiresAuthenticatedCertificate(t *testing.T) {
	var certificate []byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	certificate = server.TLS.Certificates[0].Certificate[0]
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(server.URL, "https://")
	fp, pin := tlsutil.Fingerprint(certificate), tlsutil.Pin(cert)
	for _, test := range []struct {
		name  string
		flags []string
		valid bool
	}{
		{"untrusted", nil, false},
		{"fingerprint", []string{"--fingerprint", fp}, true},
		{"public-key", []string{"--pin", pin}, true},
		{"both", []string{"--fingerprint", fp, "--pin", pin}, true},
		{"wrong-fingerprint", []string{"--fingerprint", strings.Repeat("00", 32)}, false},
		{"wrong-key", []string{"--pin", base64.StdEncoding.EncodeToString(make([]byte, 32))}, false},
		{"no-fetch-without-trust", []string{"--no-fetch"}, false},
		{"no-fetch-fingerprint-only", []string{"--no-fetch", "--fingerprint", fp}, false},
		{"no-fetch-both", []string{"--no-fetch", "--fingerprint", fp, "--pin", pin}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, err := installCommand(append([]string{"--server", host, "--token", "fixture"}, test.flags...))
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
			if !test.valid && command != "" {
				t.Fatal("failed verification emitted an install command")
			}
			if test.valid && (!strings.Contains(command, "--pinnedpubkey "+quote("sha256//"+pin)) || !strings.Contains(command, "--fingerprint "+quote(fp))) {
				t.Fatal("install command lacks verified pin or fingerprint")
			}
		})
	}
}

func TestInstallRejectsAdvertisedCertificateSubstitutionAndRedirect(t *testing.T) {
	var body []byte
	redirect := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect {
			http.Redirect(w, r, "https://example.com/cert.pem", 302)
			return
		}
		w.Write(body)
	}))
	defer server.Close()
	cert := server.Certificate()
	host := strings.TrimPrefix(server.URL, "https://")
	body = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid certificate")})
	if command, err := installCommand([]string{"--server", host, "--token", "fixture", "--pin", tlsutil.Pin(cert)}); err == nil || command != "" {
		t.Fatal("invalid advertised certificate accepted")
	}
	redirect = true
	if command, err := installCommand([]string{"--server", host, "--token", "fixture", "--pin", tlsutil.Pin(cert)}); err == nil || command != "" {
		t.Fatal("certificate redirect accepted")
	}
}

func TestInstallEndpointRejectsURLComponents(t *testing.T) {
	for _, value := range []string{"user@host", "host/path", "host?query", "host#fragment", "host:0", "host:65536", "host:bad"} {
		if _, err := installEndpoint(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	for _, value := range []string{"control.example.com", "127.0.0.1:8443", "[::1]:8443"} {
		if _, err := installEndpoint(value); err != nil {
			t.Fatal(value, err)
		}
	}
}
