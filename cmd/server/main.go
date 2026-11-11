package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/cors"

	"openwrt-parser-go/internal/config"
	httpapi "openwrt-parser-go/internal/http"
	imigrate "openwrt-parser-go/internal/migrate"
	"openwrt-parser-go/internal/openwrt"
	"openwrt-parser-go/internal/service"
	"openwrt-parser-go/internal/storage"
)

func main() {
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := imigrate.Up(cfg.SqliteDSN); err != nil {
		log.Fatal(err)
	}

	pg, err := storage.New(ctx, cfg.SqliteDSN)
	if err != nil {
		log.Fatal(err)
	}
	defer pg.Close()

	var runner openwrt.Runner
	switch cfg.OpenWrtMode {
	case "local":
		runner = openwrt.LocalRunner{}
	case "ssh":
		runner = openwrt.NewSSHRunner(cfg.OpenWrtAddr, cfg.OpenWrtUser, cfg.OpenWrtPass, cfg.OpenWrtKeyFile, cfg.OpenWrtInsecureHostKey, cfg.OpenWrtCommandTimeout)
	default:
		log.Fatalf("unsupported APP_OPENWRT_MODE: %s", cfg.OpenWrtMode)
	}

	ow := openwrt.New(
		runner,
		cfg.OpenWrtCommandTimeout,
		cfg.OpenWrtDHCPLeasesPath,
		cfg.OpenWrtConntrackPath,
		cfg.OpenWrtDNSLogLines,
		cfg.SingBoxConfigPath,
		cfg.SingBoxApplyCommand,
		openwrt.ListSpec{Name: cfg.IgnoreVPNListName, Kind: openwrt.ListKindDestination, Interface: cfg.IgnoreVPNInterface},
		openwrt.ListSpec{Name: cfg.IgnoreLanToVpnListName, Kind: openwrt.ListKindSource, Interface: cfg.IgnoreLanToVpnInterface},
	)
	defer ow.Close()

	connectionsSvc := service.NewConnectionsService(ow, cfg.IgnoreVPNListName, cfg.IgnoreLanToVpnListName)
	collectSvc := service.NewCollectService(connectionsSvc, pg, cfg.CollectInterval)
	singBoxSvc := service.NewSingBoxService(ow)
	remoteConfigSvc := service.NewRemoteConfigService(pg, singBoxSvc, cfg.UltunnelConfigsURL, cfg.UltunnelPlatform)

	go collectSvc.Run(ctx)

	h := httpapi.NewHandler(
		connectionsSvc,
		collectSvc,
		singBoxSvc,
		remoteConfigSvc,
		cfg.StaticDir,
		cfg.IgnoreVPNListName,
		cfg.IgnoreLanToVpnListName,
	)
	handler := cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	})(h.Router())

	srv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Println("HTTP listening on", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	cancel()
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(ctxShutdown)
}
