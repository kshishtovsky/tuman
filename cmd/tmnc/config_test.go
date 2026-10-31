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

// Регресс: Windows-путь в кавычках — невалидный TOML-escape.
// До фикса конфиг падал с "строка N: invalid syntax" и клиент не стартовал.
func TestLoadConfigWindowsPath(t *testing.T) {
	dir := t.TempDir()
	psk := filepath.Join(dir, "psk")
	if err := os.WriteFile(psk, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "c.toml")
	cfg := "server = \"example.com:443\"\n" +
		"psk_file = \"" + psk + "\"\n" + // именно с бэкслэшами, как отдаёт filepath на Windows
		"socks_listen = \"127.0.0.1:1080\"\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.PSKFile != psk {
		t.Fatalf("путь PSK: %q, ждали %q", c.PSKFile, psk)
	}
	if _, err := loadPSK(c.PSKFile); err != nil {
		t.Fatalf("loadPSK: %v", err)
	}
}

func TestLoadConfigServers(t *testing.T) {
	dir := t.TempDir()
	psk := filepath.Join(dir, "psk")
	if err := os.WriteFile(psk, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body+"psk_file = \""+filepath.ToSlash(psk)+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	c, err := loadConfig(write("multi.toml", `
sni = "www.example.com"
servers = ["a.example:443", "b.example:8443"]
servers_sni = ["a.example", "b.example"]
conns = 4
`))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(c.Servers) != 2 || c.Servers[0].addr != "a.example:443" || c.Servers[1].addr != "b.example:8443" {
		t.Fatalf("servers: %+v", c.Servers)
	}
	if c.Servers[0].sni != "a.example" || c.Servers[1].sni != "b.example" {
		t.Fatalf("servers_sni: %+v", c.Servers)
	}
	if c.Conns != 4 {
		t.Fatalf("conns: %d", c.Conns)
	}

	// legacy: только server — один ендпоинт, SNI из хоста
	c, err = loadConfig(write("one.toml", "server = \"x.example:443\"\n"))
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if len(c.Servers) != 1 || c.Servers[0].addr != "x.example:443" || c.Servers[0].sni != "x.example" || c.SNI != "x.example" {
		t.Fatalf("legacy servers: %+v sni=%q", c.Servers, c.SNI)
	}

	// общий sni без servers_sni — он же на всех
	c, err = loadConfig(write("shared.toml", "sni = \"cover.example\"\nservers = [\"a.example:443\", \"b.example:443\"]\n"))
	if err != nil {
		t.Fatalf("shared sni: %v", err)
	}
	if c.Servers[1].sni != "cover.example" {
		t.Fatalf("общий sni: %+v", c.Servers)
	}

	for _, bad := range []string{
		"servers = [\"a.example:443\", \"b.example:443\"]\nservers_sni = [\"a.example\"]\n",
		"servers = [\"a.example\"]\n", // нет порта
		"server = \"x.example:443\"\nservers = \"not-a-list\"\n",
	} {
		if _, err := loadConfig(write("bad.toml", bad)); err == nil {
			t.Fatalf("нет ошибки на конфиг %q", bad)
		}
	}
}
