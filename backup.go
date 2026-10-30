package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 配置备份：一个 zip 里同时放配置和证书，换机器 / 重装后导入即可直接用。
//
//	config.json                全部设置（含阿里云 AccessKey，注意保管）
//	certs/<域名>.crt|key       自动证书或手动放进去的证书（按 SNI 匹配）
//	acme_account.key           ACME 账户私钥（带上就不用重新注册账户）
//
// 只收证书/私钥类文件，证书目录里的其它杂项不会被带走。

const (
	backupCfgName   = "config.json"
	backupAcctName  = "acme_account.key"
	backupCertsDir  = "certs"
	backupMaxBytes  = 8 << 20 // 解压上限，防止恶意压缩包撑爆路由器内存
	backupMaxOneFil = 2 << 20
)

// certFileExts 是备份时收进 zip 的证书文件后缀。
func isCertFileName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".crt", ".key", ".pem", ".cer", ".csr":
		return true
	}
	return false
}

// listCertFiles 列出证书目录里需要备份的文件名（排序，保证每次导出顺序稳定）。
func listCertFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !isCertFileName(e.Name()) {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// buildBackupZip 生成备份压缩包内容。
func buildBackupZip(cfg *Config) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	cfgData, err := json.MarshalIndent(cfg.forPersist(), "", "  ")
	if err != nil {
		return nil, err
	}
	if err := zipAdd(zw, backupCfgName, append(cfgData, '\n'), 0o600); err != nil {
		return nil, err
	}

	// 证书：把证书目录里的证书和私钥一起带上
	if cfg.TLS.CertDir != "" {
		for _, name := range listCertFiles(cfg.TLS.CertDir) {
			data, rerr := os.ReadFile(filepath.Join(cfg.TLS.CertDir, name))
			if rerr != nil {
				continue // 单个文件读不到不算致命
			}
			if err := zipAdd(zw, backupCertsDir+"/"+name, data, 0o600); err != nil {
				return nil, err
			}
		}
	}

	// 手动指定的单张证书（不在证书目录里时也要备份）
	for _, p := range []string{cfg.TLS.Cert, cfg.TLS.Key} {
		if p == "" || cfg.TLS.CertDir == "" {
			continue
		}
		if strings.HasPrefix(filepath.Clean(p), filepath.Clean(cfg.TLS.CertDir)) {
			continue // 已在证书目录里，上面已收
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			continue
		}
		if err := zipAdd(zw, backupCertsDir+"/"+filepath.Base(p), data, 0o600); err != nil {
			return nil, err
		}
	}

	// ACME 账户密钥：带上它恢复后不用重新注册账户
	if cfg.baseDir != "" {
		if data, rerr := os.ReadFile(filepath.Join(cfg.baseDir, backupAcctName)); rerr == nil {
			if err := zipAdd(zw, backupAcctName, data, 0o600); err != nil {
				return nil, err
			}
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zipAdd(zw *zip.Writer, name string, data []byte, mode os.FileMode) error {
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
	hdr.SetMode(mode)
	hdr.Modified = time.Now()
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// backupContent 是解开备份包后的结果：配置原文 + 证书文件（文件名 → 内容）。
type backupContent struct {
	ConfigJSON []byte
	AccountKey []byte
	Certs      map[string][]byte
	Names      []string
}

// readBackupZip 解析备份包。只接受根目录下的 config.json 与 certs/ 下的证书文件，
// 文件名一律取 Base，杜绝 ../ 之类的路径穿越。
func readBackupZip(data []byte) (*backupContent, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("不是有效的 zip 压缩包")
	}
	out := &backupContent{Certs: map[string][]byte{}}
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(strings.TrimSpace(f.Name))
		if base == "" || base == "." || base == ".." || strings.Contains(base, "..") {
			continue
		}
		total += int64(f.UncompressedSize64)
		if total > backupMaxBytes {
			return nil, errors.New("压缩包内容过大，已中止")
		}
		if f.UncompressedSize64 > backupMaxOneFil {
			return nil, fmt.Errorf("压缩包内文件过大: %s", base)
		}
		rc, oerr := f.Open()
		if oerr != nil {
			return nil, fmt.Errorf("无法读取压缩包内的 %s: %w", base, oerr)
		}
		buf, rerr := io.ReadAll(io.LimitReader(rc, backupMaxOneFil+1))
		rc.Close()
		if rerr != nil {
			return nil, fmt.Errorf("读取压缩包内的 %s 失败: %w", base, rerr)
		}
		n := int64(len(buf))
		if n > backupMaxOneFil {
			return nil, fmt.Errorf("压缩包内文件过大: %s", base)
		}

		switch {
		case strings.EqualFold(base, backupCfgName):
			out.ConfigJSON = buf
		case strings.EqualFold(base, backupAcctName):
			out.AccountKey = buf
		case isCertFileName(base):
			out.Certs[base] = buf
			out.Names = append(out.Names, base)
		}
	}
	if len(out.ConfigJSON) == 0 {
		return nil, errors.New("压缩包里没有 config.json，不是本工具导出的备份")
	}
	sort.Strings(out.Names)
	return out, nil
}

// restoreCerts 把备份里的证书写回证书目录，返回写入的文件名。
func restoreCerts(dir string, certs map[string][]byte) ([]string, error) {
	if dir == "" || len(certs) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var names []string
	for name, data := range certs {
		if !isCertFileName(name) {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return names, fmt.Errorf("写入证书 %s 失败: %w", name, err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
