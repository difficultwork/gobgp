//
// Copyright (C) 2014-2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/osrg/gobgp/v3/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/server"
)

var opts struct {
	ConfigFile    string `short:"f" long:"config-file" description:"specifying a config file"`
	LogLevel      string `short:"l" long:"log-level" description:"specifying log level"`
	DisableStdlog bool   `long:"disable-stdlog" description:"disable standard logging"`
	CPUs          int    `long:"cpus" description:"specify the number of CPUs to be used"`
	GrpcHosts     string `long:"api-hosts" description:"specify the hosts that sbgpd listens on" default:":50051"`
	PProfHost     string `long:"pprof-host" description:"specify the host that sbgpd listens on for pprof" default:"localhost:6060"`
	PProfDisable  bool   `long:"pprof-disable" description:"disable pprof profiling"`
	TLS           bool   `long:"tls" description:"enable TLS authentication for gRPC API"`
	TLSCertFile   string `long:"tls-cert-file" description:"The TLS cert file"`
	TLSKeyFile    string `long:"tls-key-file" description:"The TLS key file"`
}

var logger = logrus.New()

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)

	_, err := flags.Parse(&opts)
	if err != nil {
		fmt.Println("Parse start params failed ", err)
		os.Exit(1)
	}

	if opts.CPUs == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		if runtime.NumCPU() < opts.CPUs {
			logger.Errorf("Only %d CPUs are available but %d is specified", runtime.NumCPU(), opts.CPUs)
			os.Exit(1)
		}
		runtime.GOMAXPROCS(opts.CPUs)
	}

	if !opts.PProfDisable {
		go func() {
			logger.Println(http.ListenAndServe(opts.PProfHost, nil))
		}()
	}

	initLog(opts.LogLevel, opts.DisableStdlog)

	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	if opts.TLS {
		creds, err := credentials.NewServerTLSFromFile(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			logger.Fatalf("Failed to generate credentials: %v", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	logger.Info("sbgpd started")
	s := server.NewBgpServer(server.GrpcListenAddress(opts.GrpcHosts), server.GrpcOption(grpcOpts), server.LoggerOption(&builtinLogger{logger: logger}))
	go s.Serve()
	defer s.Stop()

	if opts.ConfigFile != "" {
		signal.Notify(sigCh, syscall.SIGHUP)
	}
	if err = initConfig(s, opts.ConfigFile); err != nil {
		return
	}

	for sig := range sigCh {
		if sig != syscall.SIGHUP {
			break
		}

		updateConfig(s, opts.ConfigFile)
	}
}

func initLog(level string, disableStd bool) {
	switch opts.LogLevel {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	if opts.DisableStdlog {
		logger.SetOutput(io.Discard)
	} else {
		logger.SetOutput(os.Stdout)
	}
}

func initConfig(s *server.BgpServer, cf string) error {
	if cf == "" {
		return nil
	}
	cfg, err := config.ReadConfig(cf)
	if err != nil {
		logger.WithFields(logrus.Fields{"Topic": "Config", "Error": err}).Errorf("Can't read config file %s", cf)
		return err
	}
	logger.WithFields(logrus.Fields{"Topic": "Config"}).Info("Finished reading the config file")

	if err = config.InitConfig(context.Background(), s, cfg); err != nil {
		logger.WithFields(logrus.Fields{"Topic": "Config", "Error": err}).Errorf("Failed to init config %s", cf)
	}
	return err
}

func updateConfig(s *server.BgpServer, cf string) {
	if cf == "" {
		return
	}
	logger.WithFields(logrus.Fields{"Topic": "Config"}).Info("Reload the config file")
	cfg, err := config.ReadConfig(cf)
	if err != nil {
		logger.WithFields(logrus.Fields{"Topic": "Config", "Error": err}).Errorf("Can't read config file %s", cf)
		return
	}

	if err = config.UpdateConfig(context.Background(), s, cfg); err != nil {
		logger.WithFields(logrus.Fields{"Topic": "Config", "Error": err}).Errorf("Failed to init config %s", cf)
	}
}
