package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadConf(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tmns.toml")
	os.WriteFile(p, []byte(`# пример
listen = "127.0.0.1:8443"
cert = "/etc/tmn/fullchain.pem"
key = /etc/tmn/key.pem
psk_file = "/etc/tmn/psk"
cover_dir = "/var/www/tmn"

[extra]
log_level = "debug"
`), 0o600)

	c, err := loadConf(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8443" || c.Cert != "/etc/tmn/fullchain.pem" ||
		c.Key != "/etc/tmn/key.pem" || c.PSKFile != "/etc/tmn/psk" ||
		c.CoverDir != "/var/www/tmn" || c.LogLevel != "debug" {
		t.Fatalf("конфиг разобран неверно: %+v", c)
	}

	// умолчания и обязательные поля
	os.WriteFile(p, []byte("cert = \"/c\"\nkey = \"/k\"\npsk_file = \"/p\"\n"), 0o600)
	if c, err = loadConf(p); err != nil || c.Listen != ":443" || c.CoverDir != "/var/www/tmn" {
		t.Fatalf("умолчания: %+v, %v", c, err)
	}
	os.WriteFile(p, []byte("cert = \"/c\"\n"), 0o600)
	if _, err = loadConf(p); err == nil {
		t.Fatal("без key и psk_file конфиг принят")
	}
	os.WriteFile(p, []byte("cert = \"/c\"\nkey = \"/k\"\npsk_file = \"/p\"\nlisten2 = \"x\"\n"), 0o600)
	if _, err = loadConf(p); err == nil {
		t.Fatal("опечатка в ключе не замечена")
	}
}

func TestLoadPSK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "psk")

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	os.WriteFile(p, raw, 0o600)
	if got, err := loadPSK(p); err != nil || string(got) != string(raw) {
		t.Fatalf("raw: %v", err)
	}

	os.WriteFile(p, []byte(hex.EncodeToString(raw)+"\n"), 0o600)
	if got, err := loadPSK(p); err != nil || string(got) != string(raw) {
		t.Fatalf("hex: %v", err)
	}

	os.WriteFile(p, []byte("0x"+hex.EncodeToString(raw)), 0o600)
	if got, err := loadPSK(p); err != nil || string(got) != string(raw) {
		t.Fatalf("hex с 0x: %v", err)
	}

	os.WriteFile(p, []byte("short"), 0o600)
	if _, err := loadPSK(p); err == nil {
		t.Fatal("короткий PSK принят")
	}
}

// PSK 0644 читаем группой/другими — отказ (биты POSIX, на Windows пропускаем).
func TestLoadPSKPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows: os.Stat не отражает POSIX-биты")
	}
	p := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPSK(p); err == nil {
		t.Fatal("PSK 0644 принят")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPSK(p); err != nil {
		t.Fatalf("PSK 0600 отвергнут: %v", err)
	}
}

// raw-ключ не триммим: 0x0a/0x20 в нём — значимый байт.
func TestLoadPSKNoTrimRaw(t *testing.T) {
	p := filepath.Join(t.TempDir(), "psk")
	raw := bytes.Repeat([]byte{0x41}, 32)
	raw[31] = 0x0a
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadPSK(p)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("raw с 0x0a на конце: %v, %x", err, got)
	}
	// 32 байта + перевод строки = 33 байта: ошибка длины, а не тихое обрезание
	if err := os.WriteFile(p, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPSK(p); err == nil {
		t.Fatal("33 байта (32+\"\\n\") приняты как 32")
	}
}
