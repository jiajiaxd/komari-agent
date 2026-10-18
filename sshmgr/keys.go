package sshmgr

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

var keyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-dss":                            true,
	"ssh-ed25519":                        true,
	"ssh-ed448":                          true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func isKeyType(s string) bool {
	if keyTypes[s] {
		return true
	}
	// Certificate types, e.g. ssh-ed25519-cert-v01@openssh.com
	return strings.HasSuffix(s, "-cert-v01@openssh.com") && keyTypes[strings.TrimSuffix(s, "-cert-v01@openssh.com")]
}

// ParseKeyLine parses one authorized_keys line: [options] type base64 [comment].
func ParseKeyLine(line string) (v2.SSHAuthorizedKey, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return v2.SSHAuthorizedKey{}, errors.New("empty line")
	}
	var options string
	first, _ := splitField(line)
	if !isKeyType(first) {
		options, line = splitOptions(line)
		line = strings.TrimSpace(line)
	}
	keyType, rest := splitField(line)
	blob, comment := splitField(rest)
	if !isKeyType(keyType) {
		return v2.SSHAuthorizedKey{}, fmt.Errorf("unsupported key type %q", keyType)
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) < 4 {
		return v2.SSHAuthorizedKey{}, errors.New("invalid key data")
	}
	// The blob starts with its own length-prefixed type name.
	n := binary.BigEndian.Uint32(raw)
	if uint64(n)+4 > uint64(len(raw)) || string(raw[4:4+n]) != keyType {
		return v2.SSHAuthorizedKey{}, errors.New("key data does not match key type")
	}
	sum := sha256.Sum256(raw)
	return v2.SSHAuthorizedKey{
		Type:        keyType,
		Key:         blob,
		Comment:     strings.TrimSpace(comment),
		Options:     options,
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
	}, nil
}

func splitField(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

// splitOptions splits the leading options field, honoring double quotes.
func splitOptions(s string) (string, string) {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if quoted {
				i++
			}
		case '"':
			quoted = !quoted
		case ' ', '\t':
			if !quoted {
				return s[:i], s[i:]
			}
		}
	}
	return s, ""
}

// KeyLine renders a key without options, as it is installed by the panel.
func KeyLine(k v2.SSHAuthorizedKey) string {
	line := k.Type + " " + k.Key
	if k.Comment != "" {
		line += " " + k.Comment
	}
	return line
}

// ParseAuthorizedKeys returns the valid keys of an authorized_keys file.
func ParseAuthorizedKeys(content string) []v2.SSHAuthorizedKey {
	keys := []v2.SSHAuthorizedKey{}
	for _, line := range strings.Split(content, "\n") {
		if k, err := ParseKeyLine(line); err == nil {
			keys = append(keys, k)
		}
	}
	return keys
}

// EditAuthorizedKeys appends keys that are not present yet and drops every
// line whose fingerprint is in remove. Comments and unparsable lines are kept.
func EditAuthorizedKeys(content string, add []v2.SSHAuthorizedKey, remove []string) (string, bool) {
	removeSet := make(map[string]bool, len(remove))
	for _, fp := range remove {
		removeSet[fp] = true
	}
	present := make(map[string]bool)
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	out := make([]string, 0, len(lines)+len(add))
	changed := false
	for _, line := range lines {
		if k, err := ParseKeyLine(line); err == nil {
			if removeSet[k.Fingerprint] {
				changed = true
				continue
			}
			present[k.Fingerprint] = true
		}
		out = append(out, line)
	}
	for _, k := range add {
		if present[k.Fingerprint] || removeSet[k.Fingerprint] {
			continue
		}
		present[k.Fingerprint] = true
		out = append(out, KeyLine(k))
		changed = true
	}
	if len(out) == 0 {
		return "", changed
	}
	return strings.Join(out, "\n") + "\n", changed
}
