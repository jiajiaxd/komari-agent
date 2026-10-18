package sshmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	managedBegin  = "# BEGIN komari-agent managed settings"
	managedEnd    = "# END komari-agent managed settings"
	disabledMark  = "#komari-agent# "
	maxIncludeLvl = 16
)

// configFile is one sshd configuration file as read from disk.
type configFile struct {
	Path    string
	Content string
	inMatch bool // whether the file is included from within a Match block
}

// directive splits a configuration line into its lower-case keyword and its
// value. Blank lines and comments return an empty keyword.
func directive(line string) (string, string) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", ""
	}
	i := strings.IndexAny(s, " \t=")
	if i < 0 {
		return strings.ToLower(s), ""
	}
	key := strings.ToLower(s[:i])
	value := strings.TrimLeft(s[i:], " \t")
	value = strings.TrimPrefix(value, "=")
	value = strings.TrimSpace(value)
	if j := strings.Index(value, " #"); j >= 0 {
		value = strings.TrimSpace(value[:j])
	}
	return key, value
}

func unquoteFields(value string) []string {
	var out []string
	for _, f := range strings.Fields(value) {
		out = append(out, strings.Trim(f, `"`))
	}
	return out
}

type configLine struct {
	key, value string
	inMatch    bool
}

// configTree is the main configuration with every file it includes.
type configTree struct {
	files []*configFile // main file first
	lines []configLine  // directives in the order sshd reads them
}

// loadConfigTree reads the main configuration and, recursively, every file it
// includes. Relative Include paths are resolved against the directory of the
// main configuration (/etc/ssh), as sshd does.
func loadConfigTree(mainPath string) (*configTree, error) {
	content, err := os.ReadFile(mainPath)
	if err != nil {
		return nil, err
	}
	tree := &configTree{}
	seen := map[string]bool{}
	var walk func(f *configFile, level int)
	walk = func(f *configFile, level int) {
		if seen[f.Path] {
			return
		}
		seen[f.Path] = true
		tree.files = append(tree.files, f)
		inMatch := f.inMatch
		for _, line := range strings.Split(f.Content, "\n") {
			key, value := directive(line)
			switch key {
			case "":
			case "match":
				inMatch = !strings.EqualFold(strings.TrimSpace(value), "all")
			case "include":
				if level >= maxIncludeLvl {
					continue
				}
				for _, pattern := range unquoteFields(value) {
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join(filepath.Dir(mainPath), pattern)
					}
					matches, _ := filepath.Glob(pattern)
					sort.Strings(matches)
					for _, m := range matches {
						data, err := os.ReadFile(m)
						if err != nil {
							continue
						}
						walk(&configFile{Path: m, Content: string(data), inMatch: inMatch}, level+1)
					}
				}
			default:
				tree.lines = append(tree.lines, configLine{key: key, value: value, inMatch: inMatch})
			}
		}
	}
	walk(&configFile{Path: mainPath, Content: string(content)}, 0)
	return tree, nil
}

// staticSettings evaluates the configuration without sshd, used when
// `sshd -T` is not available. The first global value wins, except Port which
// accumulates.
func (t *configTree) staticSettings() map[string][]string {
	settings := map[string][]string{}
	for _, l := range t.lines {
		if l.inMatch {
			continue
		}
		if l.key == "port" {
			settings[l.key] = append(settings[l.key], l.value)
			continue
		}
		if _, ok := settings[l.key]; !ok {
			settings[l.key] = []string{strings.ToLower(l.value)}
		}
	}
	if len(settings["port"]) == 0 {
		settings["port"] = []string{"22"}
	}
	if len(settings["permitrootlogin"]) == 0 {
		settings["permitrootlogin"] = []string{"prohibit-password"}
	}
	if len(settings["passwordauthentication"]) == 0 {
		settings["passwordauthentication"] = []string{"yes"}
	}
	return settings
}

// parseEffectiveConfig parses the output of `sshd -T`.
func parseEffectiveConfig(out string) map[string][]string {
	settings := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value := directive(line)
		if key == "" {
			continue
		}
		settings[key] = append(settings[key], value)
	}
	return settings
}

func parsePorts(values []string) []int {
	var ports []int
	seen := map[int]bool{}
	for _, v := range values {
		p, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// editConfig puts every setting in a managed block at the top of the main
// configuration and comments out all other global occurrences of those
// keywords, so the managed values win regardless of include order and Port
// directives do not accumulate. It returns the new content per changed path.
// settings maps a canonical keyword (e.g. "PermitRootLogin") to its value.
func editConfig(files []*configFile, settings map[string]string) map[string]string {
	if len(files) == 0 || len(settings) == 0 {
		return nil
	}
	main := files[0]
	block, mainRest := extractManagedBlock(main.Content)
	for k, v := range settings {
		block[canonicalKey(k)] = managedSetting{key: k, value: v}
	}
	managed := map[string]bool{}
	for k := range block {
		managed[k] = true
	}

	changes := map[string]string{}
	for i, f := range files {
		content := f.Content
		if i == 0 {
			content = mainRest
		}
		edited := commentOut(content, managed, f.inMatch)
		if i == 0 {
			edited = renderManagedBlock(block) + edited
		}
		if edited != f.Content {
			changes[f.Path] = edited
		}
	}
	return changes
}

type managedSetting struct {
	key, value string
}

func canonicalKey(k string) string { return strings.ToLower(k) }

var managedOrder = []string{"port", "permitrootlogin", "passwordauthentication"}

func extractManagedBlock(content string) (map[string]managedSetting, string) {
	block := map[string]managedSetting{}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == managedBegin:
			inBlock = true
			continue
		case trimmed == managedEnd && inBlock:
			inBlock = false
			continue
		case inBlock:
			key, value := directive(line)
			if key != "" {
				fields := strings.Fields(strings.TrimSpace(line))
				name := strings.SplitN(fields[0], "=", 2)[0]
				block[key] = managedSetting{key: name, value: value}
			}
			continue
		}
		out = append(out, line)
	}
	return block, strings.Join(out, "\n")
}

func renderManagedBlock(block map[string]managedSetting) string {
	if len(block) == 0 {
		return ""
	}
	keys := make([]string, 0, len(block))
	for k := range block {
		keys = append(keys, k)
	}
	rank := func(k string) int {
		for i, o := range managedOrder {
			if o == k {
				return i
			}
		}
		return len(managedOrder)
	}
	sort.Slice(keys, func(i, j int) bool {
		if rank(keys[i]) != rank(keys[j]) {
			return rank(keys[i]) < rank(keys[j])
		}
		return keys[i] < keys[j]
	})
	var b strings.Builder
	b.WriteString(managedBegin + "\n")
	b.WriteString("# Edited from the Komari panel. Other occurrences are commented out with \"" + strings.TrimSpace(disabledMark) + "\".\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s %s\n", block[k].key, block[k].value)
	}
	b.WriteString(managedEnd + "\n")
	return b.String()
}

// commentOut disables global occurrences of the managed keywords. Lines
// inside Match blocks are conditional overrides and are left alone.
func commentOut(content string, managed map[string]bool, inMatch bool) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		key, value := directive(line)
		if key == "match" {
			inMatch = !strings.EqualFold(strings.TrimSpace(value), "all")
			continue
		}
		if key == "" || inMatch || !managed[key] {
			continue
		}
		lines[i] = disabledMark + line
	}
	return strings.Join(lines, "\n")
}
