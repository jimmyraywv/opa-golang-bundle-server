package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	Log "github.com/sirupsen/logrus"
	"jimmyray.io/opa-bundle-api/pkg/model"
	"jimmyray.io/opa-bundle-api/pkg/utils"
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
	//hostName, err := os.Hostname()
	//if err != nil {
	//	panic(err)
	//}

	fields := Log.Fields{
		//"hostname": hostName,
		"service": model.ServiceInfo.NAME,
		"id":      model.ServiceInfo.ID,
	}
	utils.InitLogs(fields, Log.ErrorLevel)

	flags = make(map[string]string)

	flagConfigFile := "Server config file"

	var serverConfigFile string

	flag.StringVar(&serverConfigFile, "config", defaultConfigFile, flagConfigFile)
	flag.Parse()

	err := model.LoadConfig(serverConfigFile)
	if err != nil {
		errorData := utils.ErrorLog{Skip: 1, Event: "error loading server config", Message: err.Error()}
		utils.LogErrors(errorData)
		panic(err)
	} else {
		utils.Logger.Info("server successfully configured")
	}

	model.ServiceInfo.NAME = model.SC.Metadata.Name
	model.ServiceInfo.ID = model.GetServiceId()

	var level Log.Level
	switch model.SC.Init.LogLevel {
	case "debug":
		level = Log.DebugLevel
	case "error":
		level = Log.ErrorLevel
	case "fatal":
		level = Log.FatalLevel
	case "warn":
		level = Log.WarnLevel
	default:
		level = Log.InfoLevel
	}

	utils.Logger.Level = level
	utils.Logger.WithFields(utils.StandardFields).WithFields(Log.Fields{"args": os.Args, "mode": "init", "logLevel": level}).Info("Service started successfully.")
	utils.Logger.Infof("Flags: %+v", flags)

	model.IC = model.InfoController{
		ServiceInfo: model.ServiceInfo,
	}

	if model.SC.Bundles.Enable {
		err = model.BuildBundle()
		if err != nil {
			utils.Logger.Errorf("build bundles failure: %+v", err)
		} else {
			utils.Logger.Debug("bundles processed")
		}
	} else {
		utils.Logger.Info("server started with no bundles")
	}

	// Registered bundles
	utils.Logger.Debugf("Registered bundles: %+v", model.RegBundles)
}

func Router() *mux.Router {
	r := mux.NewRouter().StrictSlash(true)
	return r
}

func main() {
	initServer()
	utils.Logger.WithFields(utils.StandardFields).WithFields(Log.Fields{"mode": "run"}).Infof("Listening on socket %s:%s", model.SC.Network.ServerAddress, model.SC.Network.ServerPort)

	router := Router()
	if model.SC.Init.EnableEtag {
		utils.Logger.Debug("ETag middleware enabled")
		router.Use(model.EtagMiddleware)
	} else {
		utils.Logger.Debug("ETag middleware disabled")
	}
	if utils.Logger.Level == Log.DebugLevel {
		utils.Logger.Debug("Request logging middleware enabled")
		router.Use(model.LoggingMiddleware)
	}
	if model.SC.AuthZ.Enable {
		err := model.EnableAuth()
		if err != nil {
			errorData := utils.ErrorLog{Skip: 1, Event: "AuthZ enable fail", Message: err.Error()}
			utils.LogErrors(errorData)
			//utils.Logger.Errorf("could not enabled authz: %+v", err)
			panic(err)
		}
		utils.Logger.Debug("AuthZ middleware enabled")
		router.Use(model.AuthZMiddleware)
	} else {
		utils.Logger.Debug("AuthZ middleware disabled")
	}
	if !model.SC.Init.AllowDirList {
		utils.Logger.Debug("Directory listing prevention middleware enabled")
		router.Use(model.NoListMiddleware)
	} else {
		utils.Logger.Debug("Directory listing prevention middleware disabled")
	}
	router.HandleFunc(model.SC.Network.Uris.Health, model.IC.HealthCheck).Methods(http.MethodGet)
	router.HandleFunc(model.SC.Network.Uris.Info, model.IC.GetServiceInfo).Methods(http.MethodGet)
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
	utils.Logger.Info("server stopping...")

	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		if model.SC.Bundles.PurgeBundles {
			// Purge bundles and registry
			model.PurgeBundles()
		}
		cancel()
	}()

	fmt.Println("Server Exited Gracefully")
}
