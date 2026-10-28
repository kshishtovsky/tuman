package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	psk := filepath.Join(dir, "psk")
	if err := os.WriteFile(psk, []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "c.toml")
	cfg := `
# комментарий
server = "example.com:443"
psk_file = "` + filepath.ToSlash(psk) + `"
insecure = true   # только для тестов
socks_auth = "u:p"
`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.SNI != "example.com" || !c.Insecure || c.SocksListen != "127.0.0.1:1080" || c.SocksAuth != "u:p" {
		t.Fatalf("конфиг: %+v", c)
	}
	k, err := loadPSK(c.PSKFile)
	if err != nil || len(k) != 32 || k[0] != 0x00 || k[31] != 0xff {
		t.Fatalf("psk: %v %x", err, k)
	}
	if _, err := loadConfig(filepath.Join(dir, "нет.toml")); err == nil {
		t.Fatal("нет ошибки на отсутствующий конфиг")
	}
}
