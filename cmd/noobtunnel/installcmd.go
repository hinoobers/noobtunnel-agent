package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/tlsutil"
)

// runInstall prints a command only after establishing a trusted controller pin.
func runInstall(args []string) error {
	command, err := installCommand(args)
	if err != nil {
		return err
	}
	fmt.Println(command)
	return nil
}

func installCommand(args []string) (string, error) {
	fs := newFlagSet("install")
	var (
		serverAddr  = fs.String("server", env("NOOBTUNNEL_SERVER", ""), "control node address, host:port")
		token       = fs.String("token", env("NOOBTUNNEL_TOKEN", ""), "enrollment token")
		name        = fs.String("name", "", "agent name")
		advertise   = fs.String("advertise", "", "comma separated CIDRs to advertise")
		fingerprint = fs.String("fingerprint", "", "trusted SHA-256 controller certificate fingerprint")
		publicPin   = fs.String("pin", "", "trusted base64 SHA-256 controller public key pin")
		noFetch     = fs.Bool("no-fetch", false, "use the supplied pin and fingerprint without contacting the controller")
	)
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if *serverAddr == "" {
		return "", fmt.Errorf("--server is required")
	}
	if *token == "" {
		return "", fmt.Errorf("--token is required")
	}
	endpoint, err := installEndpoint(*serverAddr)
	if err != nil {
		return "", err
	}
	fp, pin := *fingerprint, *publicPin
	if _, _, err := installTrust(fp, pin); err != nil {
		return "", err
	}
	if *noFetch {
		if fp == "" || pin == "" {
			return "", fmt.Errorf("--no-fetch requires both --pin and --fingerprint from a trusted source")
		}
	} else {
		fp, pin, err = fetchCertificate(endpoint, fp, pin)
		if err != nil {
			return "", fmt.Errorf("could not verify controller certificate: %w", err)
		}
	}

	var b strings.Builder
	b.WriteString("curl -fsSLk --retry 3 --pinnedpubkey " + quote("sha256//"+pin))
	b.WriteString(" " + quote("https://"+endpoint+"/install.sh"))
	b.WriteString(" | sudo sh -s --")
	b.WriteString(" --server " + quote(endpoint))
	b.WriteString(" --token " + quote(*token))
	b.WriteString(" --fingerprint " + quote(fp))
	b.WriteString(" --pin " + quote(pin))
	if *name != "" {
		b.WriteString(" --name " + quote(*name))
	}
	if *advertise != "" {
		b.WriteString(" --advertise " + quote(strings.ReplaceAll(*advertise, " ", "")))
	}
	return b.String(), nil
}

func installEndpoint(server string) (string, error) {
	u, err := url.Parse("https://" + server)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("--server must be a controller hostname or IP with an optional port")
	}
	port := u.Port()
	if port == "" {
		port = "8443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid controller port")
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func installTrust(fingerprint, pin string) ([]byte, []byte, error) {
	var fp, key []byte
	var err error
	if fingerprint != "" {
		normalized := strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(fingerprint)), "sha256:"), ":", "")
		fp, err = hex.DecodeString(normalized)
		if err != nil || len(fp) != sha256.Size {
			return nil, nil, fmt.Errorf("invalid SHA-256 certificate fingerprint")
		}
	}
	if pin != "" {
		key, err = base64.StdEncoding.DecodeString(pin)
		if err != nil || len(key) != sha256.Size {
			return nil, nil, fmt.Errorf("invalid SHA-256 public key pin")
		}
	}
	return fp, key, nil
}

// fetchCertificate downloads /cert.pem and derives both the fingerprint and the
// curl public key pin.
func fetchCertificate(serverAddr, fingerprint, pin string) (string, string, error) {
	fp, key, err := installTrust(fingerprint, pin)
	if err != nil {
		return "", "", err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(fp) != 0 || len(key) != 0 {
		// An operator-supplied fingerprint or public key replaces PKI validation.
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("controller certificate missing")
			}
			cert := cs.PeerCertificates[0]
			derHash := sha256.Sum256(cert.Raw)
			keyHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if len(fp) != 0 && subtle.ConstantTimeCompare(fp, derHash[:]) != 1 {
				return fmt.Errorf("controller fingerprint mismatch")
			}
			if len(key) != 0 && subtle.ConstantTimeCompare(key, keyHash[:]) != 1 {
				return fmt.Errorf("controller public key pin mismatch")
			}
			return nil
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:       12 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Get("https://" + serverAddr + "/cert.pem")
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("control node answered %s", response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<16)+1))
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(raw) > 1<<16 {
		return "", "", fmt.Errorf("control node did not return a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || !cert.Equal(response.TLS.PeerCertificates[0]) {
		return "", "", fmt.Errorf("advertised controller certificate does not match the TLS endpoint")
	}
	return tlsutil.Fingerprint(block.Bytes), tlsutil.Pin(cert), nil
}

func quote(value string) string {
	safe := value != ""
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/', r == ':', r == ',', r == '@':
		default:
			safe = false
		}
	}
	if safe {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
