package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 备份 zip 往返：配置 + 证书 + 账户密钥都能原样回来，且路径不写死。
func TestBackupZipRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.Admin.Pass = "pw"
	cfg.TLS.Enable = true
	cfg.Proxy = []Rule{{Name: "nas", Hosts: []string{"nas.example.com"}, Target: "http://192.168.1.10:5000"}}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	loaded, _, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}

	// 造两张证书与一个账户密钥
	certDir := loaded.TLS.CertDir
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"nas.example.com.crt": "CERT-DATA",
		"nas.example.com.key": "KEY-DATA",
		"notes.txt":           "不该被备份",
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(certDir, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, backupAcctName), []byte("ACCT-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	packed, err := buildBackupZip(loaded)
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	if len(packed) < 4 || packed[0] != 'P' || packed[1] != 'K' {
		t.Fatal("导出的内容不是 zip")
	}

	// 配置里不应写死自动推导出来的证书目录
	bc, err := readBackupZip(packed)
	if err != nil {
		t.Fatalf("解析备份包失败: %v", err)
	}
	var persisted Config
	if err := json.Unmarshal(bc.ConfigJSON, &persisted); err != nil {
		t.Fatalf("备份包里的配置无法解析: %v", err)
	}
	if persisted.TLS.CertDir != "" {
		t.Errorf("自动证书目录不该写进备份，得到 %q", persisted.TLS.CertDir)
	}
	if len(persisted.Proxy) != 1 || persisted.Proxy[0].Hosts[0] != "nas.example.com" {
		t.Errorf("规则没有完整带过去: %+v", persisted.Proxy)
	}

	if got := string(bc.Certs["nas.example.com.crt"]); got != "CERT-DATA" {
		t.Errorf("证书内容不对: %q", got)
	}
	if _, ok := bc.Certs["notes.txt"]; ok {
		t.Error("非证书文件不该被备份")
	}
	if string(bc.AccountKey) != "ACCT-KEY" {
		t.Error("ACME 账户密钥没有被备份")
	}

	// 恢复到另一个目录（模拟换设备）
	newDir := t.TempDir()
	names, err := restoreCerts(newDir, bc.Certs)
	if err != nil {
		t.Fatalf("恢复证书失败: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("应恢复 2 个证书文件，得到 %v", names)
	}
	data, err := os.ReadFile(filepath.Join(newDir, "nas.example.com.key"))
	if err != nil || string(data) != "KEY-DATA" {
		t.Errorf("恢复后的私钥不对: %v %q", err, data)
	}
}

// 恶意路径要被削平：解包后只能落在目标目录里。
func TestBackupRejectsPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("config.json")
	w.Write([]byte(`{"listen":":16666"}`))
	w2, _ := zw.Create("../../evil.crt")
	w2.Write([]byte("EVIL"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	bc, err := readBackupZip(buf.Bytes())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, ok := bc.Certs["evil.crt"]; !ok {
		t.Fatalf("文件名应被削平为 evil.crt，得到 %v", bc.Names)
	}

	dir := t.TempDir()
	if _, err := restoreCerts(dir, bc.Certs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.crt")); err == nil {
		t.Error("证书被写到了目标目录外面")
	}
}

func TestBackupRejectsBadZip(t *testing.T) {
	if _, err := readBackupZip([]byte("not a zip at all")); err == nil {
		t.Error("非法内容应报错")
	}
}

// 没有 config.json 的压缩包不算本工具的备份。
func TestBackupRequiresConfig(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("certs/a.crt")
	w.Write([]byte("x"))
	zw.Close()
	if _, err := readBackupZip(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "config.json") {
		t.Errorf("缺少 config.json 时应报错，得到 %v", err)
	}
}

// 默认端口：面板 18080、反代 16666；证书目录自动推导且可随配置目录迁移。
func TestDefaultPortsAndCertDir(t *testing.T) {
	d := DefaultConfig()
	if d.Listen != ":16666" {
		t.Errorf("默认反代端口应为 :16666，得到 %q", d.Listen)
	}
	if d.Admin.Listen != "0.0.0.0:18080" {
		t.Errorf("默认面板端口应为 0.0.0.0:18080，得到 %q", d.Admin.Listen)
	}

	empty := &Config{}
	if err := empty.Normalize(); err != nil {
		t.Fatalf("空配置应能补默认值: %v", err)
	}
	if empty.Listen != ":16666" || empty.Admin.Listen != "0.0.0.0:18080" {
		t.Errorf("空配置补的默认端口不对: %q %q", empty.Listen, empty.Admin.Listen)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := DefaultConfig()
	cfg.TLS.Enable = true
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	got, firstRun, err := LoadConfig(cfgPath)
	if err != nil || firstRun {
		t.Fatalf("读取配置失败: %v firstRun=%v", err, firstRun)
	}
	want := filepath.Join(dir, "certs")
	if got.TLS.CertDir != want {
		t.Errorf("证书目录应自动为 %s，得到 %s", want, got.TLS.CertDir)
	}
	if got.ACME.CertDir != want {
		t.Errorf("自动证书目录应继承 %s，得到 %s", want, got.ACME.CertDir)
	}
	// 换个安装目录读同一份配置，证书目录要跟着走
	dir2 := t.TempDir()
	data, _ := os.ReadFile(cfgPath)
	moved := filepath.Join(dir2, "config.json")
	os.WriteFile(moved, data, 0o600)
	got2, _, err := LoadConfig(moved)
	if err != nil {
		t.Fatal(err)
	}
	if want2 := filepath.Join(dir2, "certs"); got2.TLS.CertDir != want2 {
		t.Errorf("迁移后证书目录应跟着走：期望 %s，得到 %s", want2, got2.TLS.CertDir)
	}
}

// 接口级往返：导出的 zip 能被导入接口吃回去，配置与证书一起恢复。
func TestExportImportEndpoints(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := DefaultConfig()
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := NewApp(cfgPath, loaded, NewLogBuffer(50, ""))

	certDir := loaded.TLS.CertDir
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certName := "nas.example.com.crt"
	if err := os.WriteFile(filepath.Join(certDir, certName), []byte("CERT"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	a.handleConfigExport(rec, httptest.NewRequest(http.MethodGet, "/api/config/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("导出失败: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("导出应为 zip，得到 %s", ct)
	}
	blob := rec.Body.Bytes()

	// 模拟换设备：删掉证书、改掉配置
	os.Remove(filepath.Join(certDir, certName))
	next := DefaultConfig()
	next.Listen = ":17000"
	if err := a.ApplyConfig(next, true); err != nil {
		t.Fatal(err)
	}

	rec2 := httptest.NewRecorder()
	a.handleConfigImport(rec2, httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader(blob)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec2.Code, rec2.Body.String())
	}
	if _, err := os.Stat(filepath.Join(certDir, certName)); err != nil {
		t.Errorf("证书没有被恢复: %v", err)
	}
	if got := a.Config().Listen; got != ":16666" {
		t.Errorf("配置没有恢复成备份里的值，得到 %q", got)
	}

	// 坏包要被拒绝，且不能改配置
	rec3 := httptest.NewRecorder()
	a.handleConfigImport(rec3, httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader("garbage")))
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("坏包应返回 400，得到 %d", rec3.Code)
	}
	if got := a.Config().Listen; got != ":16666" {
		t.Errorf("坏包不该改动配置，得到 %q", got)
	}
}
