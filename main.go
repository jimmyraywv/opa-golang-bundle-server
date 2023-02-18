package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"jimmyray.io/opa-bundle-api/pkg/model"
	log "jimmyray.io/opa-bundle-api/pkg/logging"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	defaultConfigFile string = "server-config.json"
)

var (
	flags map[string]string
)

func initServer() {
	log.Build("", "")
	if log.Start() != nil {
		panic("could not start logging")
	}

	flags = make(map[string]string)
	flagConfigFile := "Server config file"

	var serverConfigFile string

	flag.StringVar(&serverConfigFile, "config", defaultConfigFile, flagConfigFile)
	flag.Parse()

	err := model.LoadConfig(serverConfigFile)
	if err != nil {
		log.Log.Error("error loading server config")
		panic(err)
	}
	log.Log.Info("server config successfully ingested")

	// Reinitialize logging with ingested settings
	log.Build(model.SC.Init.LogLevel, "")
	if log.Start() != nil {
		panic("could not restart logging")
	}

	model.ServiceInfo.NAME = model.SC.Metadata.Name
	model.ServiceInfo.ID = model.GetServiceId()

	log.Log.Info("Service started successfully.")
	log.Log.Infof("Flags: %+v, Args: %+v", flags, os.Args)

	model.IC = model.InfoController{
		ServiceInfo: model.ServiceInfo,
	}

	if model.SC.Bundles.Enable {
		err = model.BuildBundle()
		if err != nil {
			panic(err)
		}
		log.Log.Debug("bundles processed")
	}
	log.Log.Info("server started with no bundles")

	// Registered bundles
	reg, _ := model.RegBundles.Json()
	log.Log.Debugf("Registered bundles: %s", string(reg))
}

func Router() *mux.Router {
	r := mux.NewRouter().StrictSlash(true)
	return r
}

func main() {
	initServer()
	log.Log.Infof("Listening on socket %s:%s", model.SC.Network.ServerAddress, model.SC.Network.ServerPort)
	router := Router()

	// Middleware
	if model.SC.AuthZ.Enable {
		err := model.EnableAuth()
		if err != nil {
			panic(err)
		}
		log.Log.Debug("AuthZ middleware enabled")
		router.Use(model.AuthZMiddleware)
	}
	log.Log.Debug("AuthZ middleware disabled")

	if log.Log.Level().String() == "debug" {
		log.Log.Debug("Request logging middleware enabled")
		router.Use(model.LoggingMiddleware)
	}

	if model.SC.Init.EnableEtag {
		log.Log.Debug("ETag middleware enabled")
		router.Use(model.EtagMiddleware)
	}
	log.Log.Debug("ETag middleware disabled")

	if !model.SC.Init.AllowDirList {
		log.Log.Debug("Directory listing prevention middleware enabled")
		router.Use(model.NoListMiddleware)
	}
	log.Log.Debug("Directory listing prevention middleware disabled")

	// Handlers
	router.HandleFunc(model.SC.Network.Uris.Health, model.IC.HealthCheck).Methods(http.MethodGet)
	router.HandleFunc(model.SC.Network.Uris.Info, model.IC.GetServiceInfo).Methods(http.MethodGet)
	router.HandleFunc(model.SC.Network.Uris.Api+"/bundles", model.C.GetBundles).Methods(http.MethodGet)
	router.HandleFunc(model.SC.Network.Uris.Api+"/server/config", model.C.GetServerConfig).Methods(http.MethodGet)
	fs := http.FileServer(http.Dir(model.SC.Bundles.BundleOutDir))
	//fs := http.FileServer(http.Dir(model.SC.Bundles.BundleOutDir))
	router.PathPrefix(model.SC.Bundles.BundleUri).Handler(http.StripPrefix(model.SC.Bundles.BundleUri, fs))

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		// TLS?
		if model.SC.Network.TLS.Enable {
			fmt.Println(http.ListenAndServeTLS(model.SC.Network.ServerAddress+":"+model.SC.Network.ServerPort, model.SC.Network.TLS.Cert, model.SC.Network.TLS.Key, router))
		} else {
			fmt.Println(http.ListenAndServe(model.SC.Network.ServerAddress+":"+model.SC.Network.ServerPort, router))
		}
	}()

	<-done
	log.Log.Info("server stopping...")

	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		if model.SC.Bundles.PurgeBundles {
			// Purge bundles and registry
			model.PurgeBundles()
		}
		cancel()
	}()

	log.Log.Info("Server Exited Gracefully")
}
