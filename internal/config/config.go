// Package config loads and validates the axm-edge daemon configuration.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level daemon configuration.
type Config struct {
	Session   SessionConfig   `yaml:"session"`
	Moonraker MoonrakerConfig `yaml:"moonraker"`
	Custody   CustodyConfig   `yaml:"custody"`
	HotBuffer HotBufferConfig `yaml:"hot_buffer"`
	TPM       TPMConfig       `yaml:"tpm"`
	Uploader  UploaderConfig  `yaml:"uploader"`
}

type SessionConfig struct {
	NodeLabel string `yaml:"node_label"`
	PrinterID string `yaml:"printer_id"`
}

type MoonrakerConfig struct {
	Endpoint         string        `yaml:"endpoint"`
	APIKey           string        `yaml:"api_key"`
	ClientName       string        `yaml:"client_name"`
	ClientVersion    string        `yaml:"client_version"`
	ReconnectDelay   time.Duration `yaml:"reconnect_delay"`
	SubscribeObjects []string      `yaml:"subscribe_objects"`
}

type CustodyConfig struct {
	Period         time.Duration `yaml:"period"`
	MaxSilentTicks int           `yaml:"max_silent_ticks"`
}

type HotBufferConfig struct {
	DBPath string `yaml:"db_path"`
}

type TPMConfig struct {
	Device               string        `yaml:"device"`
	PCRs                 []uint        `yaml:"pcrs"`
	SignKeyHandle        uint32        `yaml:"sign_key_handle"`
	AKHandle             uint32        `yaml:"ak_handle"`
	QuoteInterval        time.Duration `yaml:"quote_interval"`
	QuoteOnLifecycleEdge bool          `yaml:"quote_on_lifecycle_edge"`
}

type UploaderConfig struct {
	Endpoint      string        `yaml:"endpoint"`
	BatchSize     int           `yaml:"batch_size"`
	RetryInterval time.Duration `yaml:"retry_interval"`
}

// Load reads a YAML config file from path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() Config {
	return Config{
		Session: SessionConfig{
			NodeLabel: "sfn-node-001",
			PrinterID: "printer-001",
		},
		Moonraker: MoonrakerConfig{
			Endpoint:       "ws://127.0.0.1:7125/websocket",
			ClientName:     "axm-edge",
			ClientVersion:  "0.1.0",
			ReconnectDelay: 5 * time.Second,
		},
		Custody: CustodyConfig{
			Period:         1 * time.Second,
			MaxSilentTicks: 10,
		},
		HotBuffer: HotBufferConfig{
			DBPath: "/var/lib/axm-edge/buffer.db",
		},
		TPM: TPMConfig{
			Device:               "/dev/tpmrm0",
			PCRs:                 []uint{10, 11, 12, 15},
			SignKeyHandle:        0x81000001,
			AKHandle:             0x81000002,
			QuoteInterval:        5 * time.Minute,
			QuoteOnLifecycleEdge: true,
		},
		Uploader: UploaderConfig{
			Endpoint:      "http://127.0.0.1:8080/ingest",
			BatchSize:     60,
			RetryInterval: 30 * time.Second,
		},
	}
}
