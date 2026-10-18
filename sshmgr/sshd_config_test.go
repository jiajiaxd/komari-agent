package sshmgr

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "sshd_config")
}

func TestStaticSettings(t *testing.T) {
	main := writeConfig(t, map[string]string{
		"sshd_config":                      "Include sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\nMatch User git\n  PasswordAuthentication yes\n",
		"sshd_config.d/50-cloud-init.conf": "PasswordAuthentication no\n",
		"sshd_config.d/60-port.conf":       "Port=2222\n",
	})
	tree, err := loadConfigTree(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(tree.files))
	}
	s := tree.staticSettings()
	if got := parsePorts(s["port"]); !reflect.DeepEqual(got, []int{22, 2222}) {
		t.Fatalf("ports %v", got)
	}
	if s["permitrootlogin"][0] != "yes" || s["passwordauthentication"][0] != "no" {
		t.Fatalf("settings %v", s)
	}
}

func TestEditConfig(t *testing.T) {
	main := writeConfig(t, map[string]string{
		"sshd_config":                      "# header\nInclude sshd_config.d/*.conf\n#Port 22\nPort 22\nPermitRootLogin prohibit-password\nMatch User git\n  PermitRootLogin no\n",
		"sshd_config.d/50-cloud-init.conf": "PasswordAuthentication no\n",
		"sshd_config.d/60-port.conf":       "Port 2200\n",
	})
	tree, err := loadConfigTree(main)
	if err != nil {
		t.Fatal(err)
	}
	edits := editConfig(tree.files, map[string]string{"Port": "2222", "PermitRootLogin": "yes", "PasswordAuthentication": "yes"})
	if len(edits) != 3 {
		t.Fatalf("expected 3 edited files, got %v", edits)
	}
	got := edits[main]
	if !strings.HasPrefix(got, managedBegin+"\n") {
		t.Fatalf("managed block must come first:\n%s", got)
	}
	for _, want := range []string{
		"Port 2222\nPermitRootLogin yes\nPasswordAuthentication yes\n" + managedEnd,
		"#Port 22\n" + disabledMark + "Port 22\n" + disabledMark + "PermitRootLogin prohibit-password\n",
		"Match User git\n  PermitRootLogin no\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("main config missing %q:\n%s", want, got)
		}
	}
	if edits[filepath.Join(filepath.Dir(main), "sshd_config.d/60-port.conf")] != disabledMark+"Port 2200\n" {
		t.Fatalf("drop-in port not disabled: %v", edits)
	}

	// Apply the edits, the evaluated configuration must match the request
	// and a second identical edit must be a no-op.
	for path, content := range edits {
		os.WriteFile(path, []byte(content), 0o644)
	}
	tree, _ = loadConfigTree(main)
	s := tree.staticSettings()
	if !reflect.DeepEqual(parsePorts(s["port"]), []int{2222}) || s["permitrootlogin"][0] != "yes" || s["passwordauthentication"][0] != "yes" {
		t.Fatalf("settings after edit %v", s)
	}
	if again := editConfig(tree.files, map[string]string{"Port": "2222"}); len(again) != 0 {
		t.Fatalf("expected no-op, got %v", again)
	}

	// Changing one managed value keeps the others.
	edits = editConfig(tree.files, map[string]string{"PermitRootLogin": "prohibit-password"})
	if len(edits) != 1 || !strings.Contains(edits[main], "Port 2222\nPermitRootLogin prohibit-password\nPasswordAuthentication yes\n") {
		t.Fatalf("update managed block: %v", edits)
	}
}

func TestParseEffectiveConfig(t *testing.T) {
	s := parseEffectiveConfig("port 22\nport 2222\npermitrootlogin without-password\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n")
	if !reflect.DeepEqual(parsePorts(s["port"]), []int{22, 2222}) || s["permitrootlogin"][0] != "without-password" {
		t.Fatalf("%v", s)
	}
}
