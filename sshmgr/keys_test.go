package sshmgr

import (
	"strings"
	"testing"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

const (
	testEd25519   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAHWcDI8do/tbdscczcEcjA1QUmsTqjPtOw0MOEUmjiZ alice@laptop"
	testEd25519FP = "SHA256:w87qwnJxn5SJSLnQ2tED10xlaDoJLIWW8pikpUw3OpI"
	testECDSA     = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDnufeWpg/+ubqIdn0lRr/fRfWQ8ATLmj6m99xl59blyMRdjhTi/sjMiTLpZPBXKYxdhATaCxxt9q1WQlsZo610="
	testECDSAFP   = "SHA256:DF18pn2srzgv8l2W9KrZ80fas4v6z66RlFzwxFRo/CI"
)

func TestParseKeyLine(t *testing.T) {
	k, err := ParseKeyLine(testEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if k.Type != "ssh-ed25519" || k.Comment != "alice@laptop" || k.Fingerprint != testEd25519FP {
		t.Fatalf("unexpected key %+v", k)
	}

	k, err = ParseKeyLine(`from="10.0.0.1,192.168.1.0/24",command="echo hi there" ` + testECDSA + " deploy key")
	if err != nil {
		t.Fatal(err)
	}
	if k.Options != `from="10.0.0.1,192.168.1.0/24",command="echo hi there"` || k.Comment != "deploy key" || k.Fingerprint != testECDSAFP {
		t.Fatalf("unexpected key with options %+v", k)
	}

	for _, bad := range []string{
		"",
		"# comment",
		"ssh-ed25519",
		"ssh-ed25519 not-base64!",
		// ECDSA blob declared as ed25519
		"ssh-ed25519 " + strings.Fields(testECDSA)[1],
		"foo-type AAAA",
	} {
		if _, err := ParseKeyLine(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestEditAuthorizedKeys(t *testing.T) {
	ed, _ := ParseKeyLine(testEd25519)
	ec, _ := ParseKeyLine(testECDSA)
	content := "# my keys\n" + testEd25519 + "\ngarbage line\n"

	out, changed := EditAuthorizedKeys(content, []v2.SSHAuthorizedKey{ed, ec}, nil)
	if !changed {
		t.Fatal("expected change")
	}
	want := "# my keys\n" + testEd25519 + "\ngarbage line\n" + testECDSA + "\n"
	if out != want {
		t.Fatalf("add:\n%q\nwant\n%q", out, want)
	}

	if _, changed := EditAuthorizedKeys(out, []v2.SSHAuthorizedKey{ed, ec}, nil); changed {
		t.Fatal("adding present keys must not change the file")
	}

	out, changed = EditAuthorizedKeys(out, nil, []string{testEd25519FP})
	if !changed || strings.Contains(out, "alice@laptop") || !strings.Contains(out, "# my keys") || !strings.Contains(out, "garbage line") {
		t.Fatalf("remove: %q", out)
	}

	out, changed = EditAuthorizedKeys("", []v2.SSHAuthorizedKey{ed}, nil)
	if !changed || out != testEd25519+"\n" {
		t.Fatalf("add to empty file: %q", out)
	}
	out, changed = EditAuthorizedKeys(out, nil, []string{testEd25519FP})
	if !changed || out != "" {
		t.Fatalf("remove last key: %q", out)
	}
}
