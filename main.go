/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/spheromak/vici-proxy/internal/proxy"
)

const (
	appName = "vici-proxy"

	defaultListenSocket = "/var/run/proxy.vici"
	defaultViciSocket   = "/var/run/charon.vici"

	// 2 second grace to shutdown
	ShutdownGrace = time.Second * 2
)

func main() {
	configure()

	p, err := proxy.New(
		viper.GetString("vici-socket"),
		viper.GetString("listen-socket"),
		viper.GetStringSlice("allow"),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not start proxy")
	}

	// sertup the shutdown signal handler ctx
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := <-quit
		log.Ctx(ctx).Info().Msgf("Signal '%s' caught, Server Shutting down", sig)
		cancel()
		time.Sleep(ShutdownGrace)
		os.Exit(0)
	}()

	log.Error().Err(p.Start(ctx)).Msg("shutdown")
	if err != nil {
		log.Error().Err(err).Msg("Server errr during shutdown")
		os.Exit(1)
	}

	// in theory we shouldn't get here.
	log.Info().Msg("Server Exited")
	time.Sleep(ShutdownGrace)
}

// sets up our cli args and config parsing. Fatal if it can't do these things.
func configure() {
	// setup viper:  env loading
	viper.SetEnvPrefix(strings.ToUpper(appName))           // environment variable prefix
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_")) // convert environment variable keys from - to _
	viper.AutomaticEnv()                                   // read in environment variables that match

	// Parse cli flags and load into viper
	flags := pflag.NewFlagSet("default", pflag.ExitOnError)
	flags.Bool("debug", false, "Enable debug logging.")
	flags.StringSliceP("allow", "a", proxy.DefaultAllowed, "Allowed commands.")
	flags.StringP("vici-socket", "v", defaultViciSocket, "Path to the charon.vici socket.")
	flags.StringP("listen-socket", "l", defaultListenSocket, "Path to the socket we will listen on.")

	if err := flags.Parse(os.Args); err != nil {
		log.Fatal().Err(err).Msg("couldn't parse flags ")
	}
	flags.VisitAll(func(f *pflag.Flag) {
		if err := viper.BindPFlag(f.Name, f); err != nil {
			log.Fatal().Err(err).Msg("couldn't bind flags ")
		}
	})

	// setup the logger
	setupLogging()

	log.Debug().Msgf("Allow list: %+v", viper.GetStringSlice("allow"))
}

// set defaults and level for logging
func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if viper.GetBool("debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Logging level set to DEBUG")
	}
}
