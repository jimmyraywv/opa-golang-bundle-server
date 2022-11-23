package utils

import (
	"encoding/json"
	Log "github.com/sirupsen/logrus"
	"os"
	"runtime"
)

type ErrorLog struct {
	Skip      int    `json:"skip"`
	Event     string `json:"event"`
	Message   string `json:"message"`
	ErrorData string `json:"errorData"`
}

func (e ErrorLog) String() string {
	out, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}

	return string(out)
}

var StandardFields Log.Fields

var Logger = Log.Logger{}

func InitLogs(standardFields Log.Fields, level Log.Level) {
	Logger.SetFormatter(&Log.JSONFormatter{})
	Logger.SetOutput(os.Stdout)
	Logger.SetLevel(level)

	StandardFields = standardFields
}

func LogErrors(errorData ErrorLog) {
	_, fileName, line, _ := runtime.Caller(errorData.Skip)
	Logger.WithFields(Log.Fields{"event": errorData.Event, "line": line, "file": fileName, "data": errorData.ErrorData}).Error(errorData.Message)
}
