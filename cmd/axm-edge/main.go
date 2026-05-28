// AXM Edge Attestation Daemon
//
// Transforms a standard Klipper/Moonraker-driven 3D printer into a
// zero-trust, cryptographically verified fabrication node.
//
// Usage:
//
//	axm-edge run --config /etc/axm-edge/config.yaml
//	axm-edge provision --config /etc/axm-edge/config.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bigbirdreturns/axm-sfn/internal/config"
	"github.com/bigbirdreturns/axm-sfn/internal/custody"
	"github.com/bigbirdreturns/axm-sfn/internal/hotbuffer"
	moonclient "github.com/bigbirdreturns/axm-sfn/internal/moonraker"
	tpmworker "github.com/bigbirdreturns/axm-sfn/internal/tpm"
	"github.com/bigbirdreturns/axm-sfn/internal/uploader"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "axm-edge: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("axm-edge", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/axm-edge/config.yaml", "path to config file")
	subCmd := ""
	if len(args) > 0 {
		subCmd = args[0]
		args = args[1:]
	}
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Warn("could not load config, using defaults", "error", err)
		cfg = config.DefaultConfig()
	}

	switch subCmd {
	case "provision":
		return runProvision(cfg, log)
	case "run", "":
		return runDaemon(cfg, log)
	default:
		return fmt.Errorf("unknown subcommand: %s (use 'run' or 'provision')", subCmd)
	}
}

// runProvision creates the TPM persistent keys (run once at node setup).
func runProvision(cfg config.Config, log *slog.Logger) error {
	log.Info("provisioning TPM keys", "device", cfg.TPM.Device)
	return tpmworker.ProvisionKeys(tpmworker.Config{
		Device:        cfg.TPM.Device,
		PCRs:          cfg.TPM.PCRs,
		SignKeyHandle: cfg.TPM.SignKeyHandle,
		AKHandle:      cfg.TPM.AKHandle,
	}, log)
}

// runDaemon starts all subsystems and blocks until SIGTERM/SIGINT.
func runDaemon(cfg config.Config, log *slog.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	// ── Hot Buffer ──────────────────────────────────────────────────────────
	log.Info("opening hot buffer", "path", cfg.HotBuffer.DBPath)
	buf, err := hotbuffer.Open(cfg.HotBuffer.DBPath, log)
	if err != nil {
		return fmt.Errorf("hot buffer: %w", err)
	}
	defer buf.Close()

	// ── TPM Worker ─────────────────────────────────────────────────────────
	var tpm *tpmworker.Worker
	tpm, err = tpmworker.Open(tpmworker.Config{
		Device:        cfg.TPM.Device,
		PCRs:          cfg.TPM.PCRs,
		SignKeyHandle: cfg.TPM.SignKeyHandle,
		AKHandle:      cfg.TPM.AKHandle,
	}, log)
	if err != nil {
		log.Warn("TPM unavailable — running without hardware attestation", "error", err)
		// Non-fatal: the daemon runs in software-only mode.
		tpm = nil
	}
	if tpm != nil {
		defer tpm.Close()
	}

	// ── Moonraker Client ───────────────────────────────────────────────────
	moonObjects := moonclient.DefaultSubscribeObjects()
	for _, obj := range cfg.Moonraker.SubscribeObjects {
		moonObjects[obj] = nil
	}

	moon := moonclient.NewClient(
		cfg.Moonraker.Endpoint,
		cfg.Moonraker.APIKey,
		cfg.Moonraker.ClientName,
		cfg.Moonraker.ClientVersion,
		cfg.Moonraker.ReconnectDelay,
		moonObjects,
		log,
	)

	// ── Custody Packetizer ──────────────────────────────────────────────────
	pktz := custody.NewPacketizer(custody.Config{
		NodeLabel:        cfg.Session.NodeLabel,
		PrinterID:        cfg.Session.PrinterID,
		Period:           cfg.Custody.Period,
		MaxSilentTicks:   cfg.Custody.MaxSilentTicks,
		QuoteInterval:    cfg.TPM.QuoteInterval,
		QuoteOnLifecycle: cfg.TPM.QuoteOnLifecycleEdge,
		PCRs:             cfg.TPM.PCRs,
		AKHandle:         cfg.TPM.AKHandle,
	}, buf, tpm, log)

	// ── Uploader ───────────────────────────────────────────────────────────
	up := uploader.New(
		cfg.Uploader.Endpoint,
		cfg.Uploader.BatchSize,
		cfg.Uploader.RetryInterval,
		buf,
		log,
	)

	// ── Start goroutines ───────────────────────────────────────────────────
	log.Info("axm-edge daemon starting",
		"node_label", cfg.Session.NodeLabel,
		"printer_id", cfg.Session.PrinterID,
		"moonraker", cfg.Moonraker.Endpoint)

	go moon.Run(ctx)
	go pktz.Run(ctx, moon.Updates)
	go up.Run(ctx, cfg.Session.NodeLabel+"-session") // session ID managed by packetizer in full impl

	<-ctx.Done()
	log.Info("axm-edge: shutdown signal received, draining...")
	return nil
}
