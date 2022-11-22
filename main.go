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
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	appName = "vici-proxy"

	// ShutdownGrace is the timeout waiting for server to shutdown
	ShutdownGrace = 5 * time.Second

	// viciSocketTimeout is the time to wait connecting to charon.vici
	viciSocketTimeout = 500 * time.Millisecond
)

func main() {
	configure()

	log.Info().Msg("Proxy starting")

	// sertup a signal handler ctx
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownGrace)
	log.Ctx(ctx).Info().Msg("Server Shutting down")

	defer cancel()
	//	if err := srv.Shutdown(ctx); err != nil {
	//		log.Fatal().Err(err).Msgf("Server forced to shutdown after %d seconds\n", ShutdownGrace)
	//	}
	log.Info().Msg("Server Exited")
}

// sets up our cli args and config parsing. Fatal if it can't do these things.
func configure() {
	// setup viper:  env/config loading
	viper.SetConfigName("." + appName)                     // name of config file (without extension)
	viper.AddConfigPath(".")                               // cwd is highest (preferred) config path
	viper.AddConfigPath("$HOME")                           // home directory as second search path
	viper.SetEnvPrefix(strings.ToUpper(appName))           // environment variable prefix
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_")) // convert environment variable keys from - to _
	viper.AutomaticEnv()                                   // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Err(err).Msg("couldn't load config")
	}

	// Parse cli flags and load into viper
	fs := pflag.NewFlagSet("default", pflag.ExitOnError)
	fs.Bool("debug", false, "Enable debug logging.")

	if err := fs.Parse(os.Args); err != nil {
		log.Fatal().Err(err).Msg("couldn't parse flags ")
	}
	fs.VisitAll(func(f *pflag.Flag) {
		if err := viper.BindPFlag(f.Name, f); err != nil {
			log.Fatal().Err(err).Msg("couldn't bind flags ")
		}
	})

	// setup the logger
	setupLogging()
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
