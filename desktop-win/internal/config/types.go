package config

// ServerProfile stores a WireGuard or AmneziaWG endpoint configuration.
type ServerProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PrivateKey    string `json:"privateKey"`
	PresharedKey  string `json:"presharedKey"`
	ClientIP      string `json:"clientIp"`
	DNS           string `json:"dns"`
	PeerPublicKey string `json:"peerPublicKey"`
	Endpoint      string `json:"endpoint"`
	KeepAlive     int    `json:"keepAlive"`
	MTU           int    `json:"mtu"`
	AwgParams     string `json:"awgParams"`
	UseDoH        bool   `json:"useDoH"`
	IsWarp        bool   `json:"isWarp"`
	LastPingMs    int    `json:"lastPingMs"`
}

// TelegramClientEntry represents a detected or user-added Windows Telegram desktop client.
type TelegramClientEntry struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	DisplayName  string `json:"displayName"`
	ExePath      string `json:"exePath"`
	InstallDir   string `json:"installDir"`
	IsPortable   bool   `json:"isPortable"`
	IsMsix       bool   `json:"isMsix"`
	Enabled      bool   `json:"enabled"`
	AutoDetected bool   `json:"autoDetected"`
	Running      bool   `json:"running"`
	ActiveConns  int64  `json:"activeConns"`
	RxBytes      uint64 `json:"rxBytes"`
	TxBytes      uint64 `json:"txBytes"`
}

// AppSettings holds persistent preferences and security/routing policy for Windows.
type AppSettings struct {
	Language                 string `json:"language"`
	Theme                    string `json:"theme"`
	ActiveProfileID          string `json:"activeProfileId"`
	SocksPort                int    `json:"socksPort"`
	SocksAuthEnabled         bool   `json:"socksAuthEnabled"`
	SocksUser                string `json:"socksUser"`
	SocksPass                string `json:"socksPass"`
	ProcessGuardMode         string `json:"processGuardMode"`
	KillSwitch               bool   `json:"killSwitch"`
	AutoConnectOnTelegram    bool   `json:"autoConnectOnTelegram"`
	AutoConnectOnLaunch      bool   `json:"autoConnectOnLaunch"`
	DisconnectWhenNoTelegram bool   `json:"disconnectWhenNoTelegram"`
	AutoFailover             bool   `json:"autoFailover"`
	BlockIPv6                bool   `json:"blockIpv6"`
	HttpProxyEnabled         bool   `json:"httpProxyEnabled"`
	HttpProxyPort            int    `json:"httpProxyPort"`
	UseDoH                   bool   `json:"useDoh"`
	CustomDoHURL             string `json:"customDohUrl"`
	CustomDoHServerName      string `json:"customDohServerName"`
	CustomDoHDialAddr        string `json:"customDohDialAddr"`
	StartWithWindows         bool   `json:"startWithWindows"`
	StartMinimized           bool   `json:"startMinimized"`
	MinimizeToTray           bool   `json:"minimizeToTray"`
	CallChecklistAck         bool   `json:"callChecklistAck"`
	AlwaysRunAsAdmin         bool   `json:"alwaysRunAsAdmin"`
	TelemetryConsentDecided  bool   `json:"telemetryConsentDecided"`
	TelemetryOptIn           bool   `json:"telemetryOptIn"`
	ChannelInvitedV4         bool   `json:"channelInvitedV4,omitempty"`
}

// PersistedState is the root JSON state persisted to disk (secrets DPAPI-encrypted).
type PersistedState struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Settings      AppSettings           `json:"settings"`
	Profiles      []ServerProfile       `json:"profiles"`
	CustomClients []TelegramClientEntry `json:"customClients"`
}

// DefaultSettings returns armored, Reddit-informed Windows defaults.
func DefaultSettings() AppSettings {
	return AppSettings{
		Language:              "en",
		Theme:                 "dark",
		SocksPort:             48729,
		SocksAuthEnabled:      true,
		ProcessGuardMode:      "strict",
		KillSwitch:            true,
		AutoFailover:          true,
		BlockIPv6:             true,
		HttpProxyEnabled:      false,
		HttpProxyPort:         48739,
		UseDoH:                true,
		MinimizeToTray:        true,
		StartWithWindows:      true,
		AutoConnectOnLaunch:   true,
		AutoConnectOnTelegram: true,
	}
}
