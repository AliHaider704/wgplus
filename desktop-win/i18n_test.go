package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func parseI18nEntries(t *testing.T, src string, langBlock string) map[string]string {
	t.Helper()
	marker := "  " + langBlock + ": {"
	start := strings.Index(src, marker)
	if start < 0 {
		t.Fatalf("could not find %s block in i18n.js", langBlock)
	}
	rest := src[start+len(marker):]
	end := strings.Index(rest, "\n  },")
	if end < 0 {
		t.Fatalf("could not find end of %s block in i18n.js", langBlock)
	}
	block := rest[:end]
	out := make(map[string]string)
	re := regexp.MustCompile(`(?m)^\s+([A-Za-z0-9_]+):\s*(.+?),?\s*$`)
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}
	return out
}

// extractJSLiterals pulls out quoted/backtick literal bodies from a JS expression
// so arrow parameter lists and ternary operators outside literals don't trip Latin leakage checks.
func extractJSLiterals(expr string) []string {
	var lits []string
	n := len(expr)
	for i := 0; i < n; i++ {
		ch := expr[i]
		if ch != '"' && ch != '\'' && ch != '`' {
			continue
		}
		quote := ch
		start := i + 1
		i++
		for i < n {
			c := expr[i]
			if c == '\\' {
				i += 2
				continue
			}
			if quote == '`' && c == '$' && i+1 < n && expr[i+1] == '{' {
				i += 2
				depth := 1
				for i < n && depth > 0 {
					ic := expr[i]
					if ic == '\\' {
						i += 2
						continue
					}
					if ic == '{' {
						depth++
					} else if ic == '}' {
						depth--
					}
					i++
				}
				continue
			}
			if c == quote {
				lits = append(lits, expr[start:i])
				break
			}
			i++
		}
	}
	return lits
}

func TestDesktopI18nZeroLeakageAndParity(t *testing.T) {
	rawBytes, err := os.ReadFile(filepath.Join("frontend", "dist", "i18n.js"))
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	src := string(rawBytes)

	en := parseI18nEntries(t, src, "en")
	ar := parseI18nEntries(t, src, "ar")
	if len(en) < 60 || len(ar) < 60 {
		t.Fatalf("expected >=60 i18n keys, got en=%d ar=%d", len(en), len(ar))
	}

	for k := range en {
		if _, ok := ar[k]; !ok {
			t.Errorf("missing Arabic translation for key %q", k)
		}
	}
	for k := range ar {
		if _, ok := en[k]; !ok {
			t.Errorf("missing English translation for key %q", k)
		}
	}

	reLriSpan := regexp.MustCompile(`\$\{lri\([^}]*\)\}`)
	reStringTemplateParam := regexp.MustCompile(`\$\{[A-Za-z0-9_]+\}`)
	reLatin := regexp.MustCompile(`[A-Za-z]`)
	reArabic := regexp.MustCompile(`[\x{0600}-\x{06FF}]`)

	bannedBuzz := []string{
		"ai powered", "next generation", "revolutionary", "seamless",
		"cutting edge", "intelligent", "ultimate", "effortless",
	}

	// Check every English entry
	for k, v := range en {
		if strings.Contains(v, "\u2014") {
			t.Errorf("em-dash U+2014 forbidden in en.%s", k)
		}
		if k != "langToggle" && reArabic.MatchString(v) {
			t.Errorf("Arabic script leak in en.%s: %s", k, v)
		}
		low := strings.ToLower(v)
		for _, buzz := range bannedBuzz {
			if strings.Contains(low, buzz) {
				t.Errorf("banned buzzword %q in en.%s", buzz, k)
			}
		}
	}

	// Check every Arabic entry for Latin leakage, spelling consistency, and tanween
	for k, v := range ar {
		if strings.Contains(v, "\u2014") {
			t.Errorf("em-dash U+2014 forbidden in ar.%s", k)
		}
		if strings.Contains(v, "\u0627\u064B") {
			t.Errorf("malformed tanween fath on alef in ar.%s: %s", k, v)
		}
		if strings.Contains(v, "تليجرام") || strings.Contains(v, "تيليغرام") {
			t.Errorf("non-standard Telegram spelling in ar.%s (must use تيليجرام): %s", k, v)
		}
		if k == "langToggle" {
			continue
		}
		lits := extractJSLiterals(v)
		if len(lits) == 0 {
			t.Errorf("no JS string literals parsed in ar.%s: %s", k, v)
			continue
		}
		for _, lit := range lits {
			stripped := reLriSpan.ReplaceAllString(lit, "")
			stripped = reStringTemplateParam.ReplaceAllString(stripped, "")
			if reLatin.MatchString(stripped) {
				t.Errorf("un-isolated Latin leakage in ar.%s: %s (remaining: %s)", k, v, stripped)
			}
		}
	}

	// Also verify Go tray localization has zero wrong spelling or em-dash
	trayBytes, err := os.ReadFile(filepath.Join("internal", "syswin", "tray_windows.go"))
	if err != nil {
		t.Fatalf("read tray_windows.go: %v", err)
	}
	traySrc := string(trayBytes)
	if strings.Contains(traySrc, "\u2014") {
		t.Errorf("em-dash U+2014 found in tray_windows.go")
	}
	if strings.Contains(traySrc, "تليجرام") || strings.Contains(traySrc, "تيليغرام") {
		t.Errorf("non-standard Telegram spelling in tray_windows.go")
	}
	if strings.Contains(traySrc, `lblOpen = "فتح WireGuard`) || strings.Contains(traySrc, `tg://socks"`) {
		t.Errorf("Latin leakage in Arabic tray labels inside tray_windows.go")
	}
}
