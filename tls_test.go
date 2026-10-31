package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSigned 在 dir 下生成 <name>.crt / <name>.key。
func writeSelfSigned(t *testing.T, dir, name string, dns []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dns[0]},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := os.Create(filepath.Join(dir, name+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	cf.Close()

	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kf, err := os.Create(filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}); err != nil {
		t.Fatal(err)
	}
	kf.Close()
}

// 客户端不发 SNI（用 IP 直连）时要能完成握手，好让后面的 403 页面露出来；
// 但发了不认识的名字仍然拒绝，别把别人的域名当自己的用。
func TestGetCertificate(t *testing.T) {
	dir := t.TempDir()
	writeSelfSigned(t, dir, "a.example.com", []string{"a.example.com"})
	writeSelfSigned(t, dir, "b.example.com", []string{"b.example.com"})

	logs := NewLogBuffer(50, "")
	m := newCertManager(TLSConfig{CertDir: dir}, logs)
	if err := m.reload(); err != nil {
		t.Fatalf("加载证书失败: %v", err)
	}

	// 没有 SNI
	if c, err := m.GetCertificate(tlsHello("")); err != nil || c == nil {
		t.Fatalf("空 SNI 应能拿到一张证书，得到 %v / %v", c, err)
	}

	// 精确匹配
	if c, err := m.GetCertificate(tlsHello("b.example.com")); err != nil || c == nil {
		t.Fatalf("b.example.com 应匹配到证书: %v", err)
	} else if leaf := leafCN(t, c); leaf != "b.example.com" {
		t.Errorf("b.example.com 匹配到了 %s 的证书", leaf)
	}

	// 不认识的名字要拒绝
	if _, err := m.GetCertificate(tlsHello("evil.example.net")); err == nil {
		t.Error("未知 SNI 不该返回证书")
	}
}

func tlsHello(sni string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: sni}
}

func leafCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	if c == nil || len(c.Certificate) == 0 {
		t.Fatal("空证书")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}
