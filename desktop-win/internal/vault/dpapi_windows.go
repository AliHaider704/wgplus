package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/windows"
	"wgplus-win/internal/config"
)

const (
	dpapiPrefix    = "dpapi:"
	backupFormatV1 = "wgplus-backup-v1"
)

var dpapiEntropy = []byte("WireGuardPlus-Windows-DPAPI-v1")

// Store manages DPAPI-encrypted state persistence and portable-mode detection.
type Store struct {
	mu         sync.Mutex
	dataDir    string
	statePath  string
	isPortable bool
}

// ResolveDataDir determines whether portable mode is active beside the executable
// (presence of portable.flag or wgplus-data directory) or standard %LOCALAPPDATA%\WireGuardPlus.
func ResolveDataDir(exePath string) (dataDir string, portable bool) {
	if strings.TrimSpace(exePath) != "" {
		exeDir := filepath.Dir(exePath)
		flagPath := filepath.Join(exeDir, "portable.flag")
		portableDir := filepath.Join(exeDir, "wgplus-data")
		if _, err := os.Stat(flagPath); err == nil {
			return portableDir, true
		}
		if st, err := os.Stat(portableDir); err == nil && st.IsDir() {
			return portableDir, true
		}
	}
	localApp := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if localApp == "" {
		if cfgDir, err := os.UserConfigDir(); err == nil {
			localApp = cfgDir
		} else {
			localApp = os.TempDir()
		}
	}
	return filepath.Join(localApp, "WireGuardPlus"), false
}

// NewStore opens or initializes the vault in the resolved data directory.
func NewStore() (*Store, error) {
	exePath, _ := os.Executable()
	dir, portable := ResolveDataDir(exePath)
	return NewStoreAt(dir, portable)
}

// NewStoreAt opens or initializes the vault at an explicit directory (useful for tests).
func NewStoreAt(dir string, portable bool) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed creating vault dir: %w", err)
	}
	return &Store{
		dataDir:    dir,
		statePath:  filepath.Join(dir, "state.json"),
		isPortable: portable,
	}, nil
}

func (s *Store) DataDir() string  { return s.dataDir }
func (s *Store) IsPortable() bool { return s.isPortable }
func (s *Store) WebviewDirForElevation(elevated bool) string {
	if elevated {
		return filepath.Join(s.dataDir, "webview2-admin")
	}
	return filepath.Join(s.dataDir, "webview2")
}
func (s *Store) WebviewDir() string {
	return s.WebviewDirForElevation(windows.GetCurrentProcessToken().IsElevated())
}

func makeDataBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{
		Size: uint32(len(b)),
		Data: &b[0],
	}
}

func ProtectDPAPI(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	inBlob := makeDataBlob([]byte(plain))
	entBlob := makeDataBlob(dpapiEntropy)
	var outBlob windows.DataBlob
	if err := windows.CryptProtectData(inBlob, nil, entBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &outBlob); err != nil {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}
	if outBlob.Data != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))
	}
	if outBlob.Size == 0 || outBlob.Data == nil {
		return "", errors.New("CryptProtectData produced empty blob")
	}
	raw := unsafe.Slice(outBlob.Data, outBlob.Size)
	return dpapiPrefix + base64.StdEncoding.EncodeToString(raw), nil
}

func UnprotectDPAPI(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, dpapiPrefix) {
		return encoded, nil
	}
	b64 := strings.TrimPrefix(encoded, dpapiPrefix)
	cipherBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid DPAPI base64: %w", err)
	}
	inBlob := makeDataBlob(cipherBytes)
	entBlob := makeDataBlob(dpapiEntropy)
	var outBlob windows.DataBlob
	if err := windows.CryptUnprotectData(inBlob, nil, entBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &outBlob); err != nil {
		return "", fmt.Errorf("CryptUnprotectData failed: %w", err)
	}
	if outBlob.Data != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))
	}
	if outBlob.Size == 0 || outBlob.Data == nil {
		return "", nil
	}
	plain := make([]byte, outBlob.Size)
	copy(plain, unsafe.Slice(outBlob.Data, outBlob.Size))
	return string(plain), nil
}

func GenerateRandomCredential(length int) string {
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	if length <= 0 {
		length = 16
	}
	raw := make([]byte, length)
	_, _ = rand.Read(raw)
	out := make([]byte, length)
	for i, b := range raw {
		out[i] = charset[int(b)%len(charset)]
	}
	return string(out)
}

// Load reads and decrypts state.json, initializing armored defaults on first run.
func (s *Store) Load() (config.PersistedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			st := config.PersistedState{
				SchemaVersion: 2,
				Settings:      config.DefaultSettings(),
				Profiles:      []config.ServerProfile{},
				CustomClients: []config.TelegramClientEntry{},
			}
			st.Settings.SocksUser = "wgp_" + GenerateRandomCredential(8)
			st.Settings.SocksPass = GenerateRandomCredential(22)
			if saveErr := s.saveLocked(st); saveErr != nil {
				return st, saveErr
			}
			return st, nil
		}
		return config.PersistedState{}, err
	}

	var st config.PersistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return config.PersistedState{}, fmt.Errorf("corrupt state.json: %w", err)
	}
	if st.SchemaVersion < 2 {
		// v1.7.1 migration: always-on defaults so the tunnel survives reboot/sleep without manual clicks.
		st.Settings.StartWithWindows = true
		st.Settings.AutoConnectOnLaunch = true
		st.Settings.AutoConnectOnTelegram = true
		st.Settings.MinimizeToTray = true
		st.SchemaVersion = 2
	}
	if st.Settings.SocksPort <= 0 {
		st.Settings.SocksPort = 48729
	}
	if st.Settings.HttpProxyPort <= 0 {
		st.Settings.HttpProxyPort = 48739
	}
	if st.Settings.Language != "ar" {
		st.Settings.Language = "en"
	}
	if st.Settings.Theme != "light" {
		st.Settings.Theme = "dark"
	}
	if st.Settings.ProcessGuardMode != "log_only" {
		st.Settings.ProcessGuardMode = "strict"
	}

	if st.Settings.SocksPass != "" {
		dec, dErr := UnprotectDPAPI(st.Settings.SocksPass)
		if dErr != nil {
			return st, fmt.Errorf("failed decrypting SOCKS5 credential: %w", dErr)
		}
		st.Settings.SocksPass = dec
	}
	if st.Settings.SocksUser == "" {
		st.Settings.SocksUser = "wgp_" + GenerateRandomCredential(8)
	}
	if st.Settings.SocksPass == "" {
		st.Settings.SocksPass = GenerateRandomCredential(22)
	}

	for i := range st.Profiles {
		if st.Profiles[i].PrivateKey != "" {
			dec, dErr := UnprotectDPAPI(st.Profiles[i].PrivateKey)
			if dErr != nil {
				return st, fmt.Errorf("failed decrypting profile %q PrivateKey: %w", st.Profiles[i].Name, dErr)
			}
			st.Profiles[i].PrivateKey = dec
		}
		if st.Profiles[i].PresharedKey != "" {
			dec, dErr := UnprotectDPAPI(st.Profiles[i].PresharedKey)
			if dErr != nil {
				return st, fmt.Errorf("failed decrypting profile %q PresharedKey: %w", st.Profiles[i].Name, dErr)
			}
			st.Profiles[i].PresharedKey = dec
		}
	}
	return st, nil
}

// Save DPAPI-encrypts all secrets and atomically persists state.json.
func (s *Store) Save(st config.PersistedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(st)
}

func (s *Store) saveLocked(st config.PersistedState) error {
	sealed := st
	sealed.SchemaVersion = 2
	sealed.Profiles = make([]config.ServerProfile, len(st.Profiles))
	copy(sealed.Profiles, st.Profiles)

	if sealed.Settings.SocksPass != "" {
		enc, err := ProtectDPAPI(sealed.Settings.SocksPass)
		if err != nil {
			return err
		}
		sealed.Settings.SocksPass = enc
	}
	for i := range sealed.Profiles {
		if sealed.Profiles[i].PrivateKey != "" {
			enc, err := ProtectDPAPI(sealed.Profiles[i].PrivateKey)
			if err != nil {
				return err
			}
			sealed.Profiles[i].PrivateKey = enc
		}
		if sealed.Profiles[i].PresharedKey != "" {
			enc, err := ProtectDPAPI(sealed.Profiles[i].PresharedKey)
			if err != nil {
				return err
			}
			sealed.Profiles[i].PresharedKey = enc
		}
	}

	payload, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := fmt.Sprintf("%s.tmp.%d", s.statePath, os.Getpid())
	if err := os.WriteFile(tmpPath, payload, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.statePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

type portableBackupEnvelope struct {
	Format     string `json:"format"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// ExportEncryptedBackup encrypts the entire state (profiles, settings, custom clients)
// using Argon2id + AES-256-GCM so portable users can transfer configurations across Windows PCs.
func ExportEncryptedBackup(st config.PersistedState, passphrase string) ([]byte, error) {
	if len(passphrase) < 4 {
		return nil, errors.New("passphrase must be at least 4 characters")
	}
	plain, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, 2, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, []byte(backupFormatV1))
	env := portableBackupEnvelope{
		Format:     backupFormatV1,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	}
	return json.MarshalIndent(env, "", "  ")
}

// ImportEncryptedBackup decrypts a portable Argon2id + AES-256-GCM backup bundle.
func ImportEncryptedBackup(raw []byte, passphrase string) (config.PersistedState, error) {
	var env portableBackupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return config.PersistedState{}, fmt.Errorf("invalid backup file: %w", err)
	}
	if env.Format != backupFormatV1 {
		return config.PersistedState{}, fmt.Errorf("unsupported backup format %q", env.Format)
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) < 8 {
		return config.PersistedState{}, errors.New("corrupt backup salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return config.PersistedState{}, errors.New("corrupt backup nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return config.PersistedState{}, errors.New("corrupt backup ciphertext")
	}
	key := argon2.IDKey([]byte(passphrase), salt, 2, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return config.PersistedState{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return config.PersistedState{}, err
	}
	if len(nonce) != gcm.NonceSize() {
		return config.PersistedState{}, errors.New("invalid backup nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(backupFormatV1))
	if err != nil {
		return config.PersistedState{}, errors.New("wrong passphrase or tampered backup")
	}
	var out config.PersistedState
	if err := json.Unmarshal(plain, &out); err != nil {
		return config.PersistedState{}, err
	}
	return out, nil
}
