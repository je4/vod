package main

import (
	"flag"
	"fmt"
	"github.com/je4/certloader/v2/pkg/loader"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/je4/vod/config"
	"github.com/je4/vod/pkg/web"
	"github.com/rs/zerolog"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var configfile = flag.String("config", "", "location of toml configuration file")

func main() {
	flag.Parse()

	var cfgFS fs.FS
	var cfgFile string
	if *configfile != "" {
		cfgFS = os.DirFS(filepath.Dir(*configfile))
		cfgFile = filepath.Base(*configfile)
	} else {
		cfgFS = config.ConfigFS
		cfgFile = "vod.toml"
	}

	conf := &VODConfig{
		LocalAddr: "localhost:8443",
		//ResolverTimeout: config.Duration(10 * time.Minute),
		ExternalAddr: "https://localhost:8443",
		LogLevel:     "DEBUG",
	}
	if err := LoadVODConfig(cfgFS, cfgFile, conf); err != nil {
		log.Fatalf("cannot load toml from [%v] %s: %v", cfgFS, cfgFile, err)
	}

	// create logger instance
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("cannot get hostname: %v", err)
	}

	logLevel, err := zerolog.ParseLevel(conf.LogLevel)
	if err != nil {
		panic(fmt.Sprintf("cannot parse log level '%s': %v", conf.LogLevel, err))
	}
	_logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Str("host", hostname).
		Str("addr", conf.LocalAddr).
		Logger().
		Level(logLevel)
	var logger zLogger.ZLogger = &_logger

	webTLSConfig, webLoader, err := loader.CreateServerLoader(false, conf.WebTLS, nil, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot create server loader")
	}
	defer webLoader.Close()

	ctrl, err := web.NewMainController(
		conf.LocalAddr,
		conf.ExternalAddr,
		webTLSConfig,
		conf.JWTKey,
		conf.JWTAlg,
		time.Duration(conf.CacheTimeout),
		logger)
	if err != nil {
		logger.Fatal().Msgf("cannot create controller: %v", err)
	}
	var wg = &sync.WaitGroup{}
	ctrl.Start(wg)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	fmt.Println("press ctrl+c to stop server")
	s := <-done
	fmt.Println("got signal:", s)

	ctrl.GracefulStop()
	wg.Wait()
}
