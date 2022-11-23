package model

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
)

var serviceId = uuid.New()

var (
	PageNotFound string = "404 page not found"
	Forbidden    string = "403 forbidden"
)

func GetServiceId() string {
	return serviceId.String()
}

type info struct {
	NAME string `json:"service-name"`
	ID   string `json:"service-id"`
}

func (i info) String() string {
	out, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}

	return string(out)
}

var ServiceInfo = info{}

type InfoController struct {
	ServiceInfo info
}

var (
	IC InfoController
)

func (ic InfoController) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "OK")
}

func (ic InfoController) GetServiceInfo(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, ServiceInfo.String())
}
