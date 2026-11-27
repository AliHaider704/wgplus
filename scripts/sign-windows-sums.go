//go:build ignore

// Offline Ed25519 key generator, signer, and verifier for WireGuard Plus Windows releases.
// Usage:
//   go run scripts/sign-windows-sums.go -keygen .offline_keys [-force]
//   go run scripts/sign-windows-sums.go -sign -key .offline_keys/updater_ed25519_primary.key -in dist/SHA256SUMS-windows.txt -out dist/SHA256SUMS-windows.txt.sig
//   go run scripts/sign-windows-sums.go -verify -pub <hex1[,hex2]> -in dist/SHA256SUMS-windows.txt -sig dist/SHA256SUMS-windows.txt.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	keygenDir := flag.String("keygen", "", "Directory to write offline primary + backup Ed25519 keypairs")
	force := flag.Bool("force", false, "Overwrite existing keys during -keygen")
	signMode := flag.Bool("sign", false, "Sign checksums file")
	verifyMode := flag.Bool("verify", false, "Verify checksums signature")
	keyFile := flag.String("key", "", "Path to 128-hex private key file (falls back to WGPLUS_UPDATER_ED25519_PRIV_HEX env var)")
	pubList := flag.String("pub", "", "Comma-separated 64-hex Ed25519 public keys for -verify")
	inPath := flag.String("in", "", "Input checksums file (exact bytes signed)")
	outPath := flag.String("out", "", "Output .sig file for -sign")
	sigPath := flag.String("sig", "", "Input .sig file for -verify")
	flag.Parse()

	if *keygenDir != "" {
		if err := runKeygen(*keygenDir, *force); err != nil {
			fatalf("keygen failed: %v", err)
		}
		return
	}
	if *signMode {
		if err := runSign(*keyFile, *inPath, *outPath); err != nil {
			fatalf("sign failed: %v", err)
		}
		return
	}
	if *verifyMode {
		if err := runVerify(*pubList, *inPath, *sigPath); err != nil {
			fatalf("verify failed: %v", err)
		}
		return
	}
	fatalf("must pass one of -keygen, -sign, or -verify")
}

func runKeygen(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	primPrivPath := filepath.Join(dir, "updater_ed25519_primary.key")
	primPubPath := filepath.Join(dir, "updater_ed25519_primary.pub")
	backPrivPath := filepath.Join(dir, "updater_ed25519_backup.key")
	backPubPath := filepath.Join(dir, "updater_ed25519_backup.pub")
	readmePath := filepath.Join(dir, "README-OFFLINE-KEYS.txt")

	if !force {
		for _, p := range []string{primPrivPath, primPubPath, backPrivPath, backPubPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("refusing to overwrite existing key file %s (pass -force only if rotating intentionally)", p)
			}
		}
	}

	primPub, primPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	backPub, backPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if err := os.WriteFile(primPrivPath, []byte(hex.EncodeToString(primPriv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(primPubPath, []byte(hex.EncodeToString(primPub)+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(backPrivPath, []byte(hex.EncodeToString(backPriv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(backPubPath, []byte(hex.EncodeToString(backPub)+"\n"), 0o644); err != nil {
		return err
	}

	readme := `WireGuard Plus Windows Updater — Offline Ed25519 Signing Keys
==============================================================

CRITICAL SECURITY RULES / قواعد الأمان الحرجة:
1. NEVER commit *.key files or paste their contents into GitHub / chats.
   لا ترفع ملفات .key إلى GitHub أو ترسل محتواها أبداً.
2. Back up both 'updater_ed25519_primary.key' AND 'updater_ed25519_backup.key'
   offline (e.g., encrypted USB / password manager).
   احتفظ بنسخة احتياطية offline للمفتاحين الأساسي والاحتياطي في مكان آمن.
3. Both corresponding public keys (.pub) are embedded into updater.go.
   If the primary private key is ever lost or needs rotation, you can sign
   'SHA256SUMS-windows.txt' using 'updater_ed25519_backup.key' and older clients
   will still accept and verify the rescue release!
   المفتاحان العامان مدمجان في الكود: لو ضاع المفتاح الأساسي، وقّع بالاحتياطي
   لتستمر النسخ القديمة بالتحقق وتحديث نفسها بسلاسة.

How to sign a release locally / توقيع الإصدار محلياً:
  scripts\build-windows.ps1 automatically signs dist\SHA256SUMS-windows.txt ->
  dist\SHA256SUMS-windows.txt.sig when .offline_keys\updater_ed25519_primary.key
  is present (or WGPLUS_UPDATER_ED25519_PRIV_HEX is set in environment).

Note on Windows SmartScreen:
  Ed25519 verification protects against GitHub account compromise and tampering,
  but Windows SmartScreen warnings persist until a commercial EV/Authenticode
  certificate is also purchased.
`
	return os.WriteFile(readmePath, []byte(readme), 0o600)
}

func loadPrivateKey(keyFile string) (ed25519.PrivateKey, error) {
	var rawHex string
	if strings.TrimSpace(keyFile) != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		rawHex = strings.TrimSpace(string(b))
	} else {
		rawHex = strings.TrimSpace(os.Getenv("WGPLUS_UPDATER_ED25519_PRIV_HEX"))
	}
	if rawHex == "" {
		return nil, fmt.Errorf("missing Ed25519 private key (-key file or WGPLUS_UPDATER_ED25519_PRIV_HEX)")
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length (want %d hex bytes)", ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func runSign(keyFile, inPath, outPath string) error {
	if inPath == "" || outPath == "" {
		return fmt.Errorf("-in and -out are required for -sign")
	}
	priv, err := loadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, data)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, data, sig) {
		return fmt.Errorf("self-verification failed after signing")
	}
	line := hex.EncodeToString(sig) + "  " + filepath.Base(inPath) + "\n"
	return os.WriteFile(outPath, []byte(line), 0o644)
}

func runVerify(pubList, inPath, sigPath string) error {
	if pubList == "" || inPath == "" || sigPath == "" {
		return fmt.Errorf("-pub, -in, and -sig are required for -verify")
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	fields := strings.Fields(strings.TrimSpace(string(sigRaw)))
	if len(fields) == 0 {
		return fmt.Errorf("empty signature file")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(fields[0]))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid Ed25519 signature hex")
	}
	for _, p := range strings.Split(pubList, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pubBytes, pErr := hex.DecodeString(p)
		if pErr != nil || len(pubBytes) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
			fmt.Printf("OK verified Ed25519 signature against public key %s\n", p[:12]+"...")
			return nil
		}
	}
	return fmt.Errorf("signature did not verify against any provided Ed25519 public key")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
