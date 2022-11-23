package model

import (
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"jimmyray.io/opa-bundle-api/pkg/utils"
)

const StaticJson string = `
{
  "metadata": {
    "name": "opa-bundle-server",
    "tags": {
      "owner": "jimmy",
      "env": "dev",
      "billing": "lob-cc"
    }
  },
  "network": {
    "server-address": "10.0.2.2",
    "server-port": "8443",
    "tls": {
      "enable": true,
      "cert": "tls/localhost.crt",
      "key": "tls/localhost.key"
    },
    "uris": {
      "health": "/healthz",
      "info": "/info"
    }
  },
  "init": {
    "allow-dir-list": false,
    "enable-request-logging": true,
    "enable-etag": true,
    "log-level": "debug"
  },
  "authz": {
    "enable": false,
    "secrets": "authz/tokens.json"
  },
  "bundles": {
    "enable":true,
    "load-registry": false,
    "persist-registry": false,
    "purge-bundles": false,
    "bundle-uri": "/v1/bundles",
    "bundle-out-dir": "bundles",
    "bundles": [
      {
        "build": true,
        "bundle-name": "main",
        "bundle-file-name": "signed-main",
        "bundle-ts": false,
        "bundle-in-dir": "bundle-material",
        "bundle-out-dir": "bundles",
        "bundle-revision": "v0.1.0",
        "bundle-roots": [
          "pacbook","somewhere","somplace"
        ],
        "bundle-ignore-files":[".DS_Store",".manifest"],
        "bundle-signing": {
          "enable": true,
          "signing-alg": "RS256",
          "signing-key": "keys/key.pem",
          "signing-key-id": "main-key"
        }
      },
      {
        "build": true,
        "bundle-name": "jimmy",
        "bundle-file-name": "signed-jimmy",
        "bundle-ts": false,
        "bundle-in-dir": "bundle-material",
        "bundle-out-dir": "bundles",
        "bundle-revision": "v0.1.0",
        "bundle-roots": [
          "jimmy"
        ],
        "bundle-ignore-files":[".DS_Store",".manifest"],
        "bundle-signing": {
          "enable": true,
          "signing-alg": "RS256",
          "signing-key": "keys/key.pem",
          "signing-key-id": "main-key"
        }
      },
      {
        "build": true,
        "bundle-name": "ray",
        "bundle-file-name": "unsigned-ray",
        "bundle-ts": false,
        "bundle-in-dir": "bundle-material",
        "bundle-out-dir": "bundles",
        "bundle-revision": "v0.1.0",
        "bundle-roots": [
          "ray"
        ],
        "bundle-ignore-files":[".DS_Store",".manifest"],
        "bundle-signing": {
          "enable": false,
          "signing-alg": "RS256",
          "signing-key": "keys/key.pem",
          "signing-key-id": "main-key"
        }
      }
    ]
  }
}
`

var SC = Config{}

type Config struct {
	AuthZ struct {
		Enable  bool   `json:"enable"` // validate:"required"`
		Secrets string `json:"secrets"`
	} `json:"authz" validate:"required"`
	Bundles struct {
		//BundleOutDir string `json:"bundle-out-dir"`
		BundleUri    string `json:"bundle-uri" validate:"required"`
		BundleOutDir string `json:"bundle-out-dir" validate:"required"`
		Bundles      []struct {
			Build             bool     `json:"build"`
			BundleName        string   `json:"bundle-name"`
			BundleFileName    string   `json:"bundle-file-name"`
			BundleTs          bool     `json:"bundle-ts"`
			BundleIgnoreFiles []string `json:"bundle-ignore-files"`
			BundleInDir       string   `json:"bundle-in-dir"`
			BundleOutDir      string   `json:"bundle-out-dir"`
			BundleRevision    string   `json:"bundle-revision"`
			BundleRoots       []string `json:"bundle-roots"`
			BundleSigning     struct {
				Enable       bool   `json:"enable"`
				SigningAlg   string `json:"signing-alg"`
				SigningKey   string `json:"signing-key"`
				SigningKeyID string `json:"signing-key-id"`
			} `json:"bundle-signing"`
		} `json:"bundles"`
		Enable          bool `json:"enable"`
		LoadRegistry    bool `json:"load-registry"`
		PersistRegistry bool `json:"persist-registry"`
		PurgeBundles    bool `json:"purge-bundles"`
	} `json:"bundles"`
	Init struct {
		AllowDirList          bool   `json:"allow-dir-list"`
		EnableEtag            bool   `json:"enable-etag"`
		EnableLRequestLogging bool   `json:"enable-request-logging"`
		LogLevel              string `json:"log-level"`
	} `json:"init" validate:"required"`
	Metadata struct {
		Name string `json:"name" validate:"required"`
		Tags struct {
			Billing string `json:"billing"`
			Env     string `json:"env"`
			Owner   string `json:"owner"`
		} `json:"tags"`
	} `json:"metadata" validate:"required"`
	Network struct {
		ServerAddress string `json:"server-address" validate:"required"`
		ServerPort    string `json:"server-port" validate:"required"`
		TLS           struct {
			Cert   string `json:"cert"`
			Enable bool   `json:"enable" validate:"required"`
			Key    string `json:"key"`
		} `json:"tls"`
		Uris struct {
			Health string `json:"health" validate:"required"`
			Info   string `json:"info" validate:"required"`
		} `json:"uris"`
	} `json:"network" validate:"required"`
}

func (c Config) Json() (string, error) {
	out, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func LoadConfig(configFile string) error {
	bytes, err := utils.ReadFile(configFile)
	if err == nil {
		utils.Logger.Debugf("JSON from file: %s", string(bytes))
	}

	err = json.Unmarshal(bytes, &SC)
	if err != nil {
		utils.Logger.Errorf("could not unmarshal JSON: %+v", err)
		return err
	}

	cj, _ := SC.Json()
	utils.Logger.Debugf("Server Config=%s", cj)

	// Validate
	v := validator.New()
	v.RegisterStructValidation(DependencyValidator, SC)
	err = v.Struct(SC)
	if err != nil {
		utils.Logger.Errorf("could not validate config struct: %+v", err)
		return err
	}

	return nil
}

func DependencyValidator(sl validator.StructLevel) {
	c := sl.Current().Interface().(Config)

	if c.Network.TLS.Enable {
		if len(c.Network.TLS.Cert) == 0 {
			sl.ReportError(c.Network.TLS.Cert, "Network.TLS.Cert",
				"Network.TLS.Cert", "requiredfortls", "")
		}
		if len(c.Network.TLS.Key) == 0 {
			sl.ReportError(c.Network.TLS.Key, "Network.TLS.Key",
				"Network.TLS.Key", "requiredfortls", "")
		}
	}
}
