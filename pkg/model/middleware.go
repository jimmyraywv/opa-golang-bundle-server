package model

import (
	"encoding/json"
	"github.com/cristalhq/jwt/v4"
	log "jimmyray.io/opa-bundle-api/pkg/logging"
	"jimmyray.io/opa-bundle-api/pkg/utils"
	"net/http"
	"path"
	"strings"
	"time"
)

type AuthzData struct {
	Allowed []struct {
		ID           string   `json:"id"`
		Secret       string   `json:"secret"`
		Audience     string   `json:"audience"`
		Entitlements []string `json:"entitlements"`
	} `json:"allowed"`
}

func (a AuthzData) Json() ([]byte, error) {
	out, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	return out, nil
}

var AD = AuthzData{}

func EnableAuth() error {
	bytes, err := utils.ReadFile(SC.AuthZ.Secrets)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, &AD)
	if err != nil {
		log.Log.Errorf("could not unmarshal JSON", err)
		return err
	}

	s, _ := AD.Json()
	log.Log.Debugf("AuthZ JSON: %s", string(s))
	return nil
}

func AuthZMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var header = r.Header.Get("Authorization")
		header = strings.TrimSpace(header)

		if len(header) <= 7 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(Unauthorized))
			return
		}

		token := header[7:]

		valid, err := parseJwt(token, r.URL.Path)
		if err != nil {
			log.Log.Errorf("JWT parsing: %v", err)

			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(Unauthorized))
			return
		}

		if !valid {
			log.Log.Debug("Invalid JWT")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(Unauthorized))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func EtagMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), SC.Bundles.BundleUri) {
			fileName := path.Base(r.URL.String())
			if _, there := RegBundles.Bundles[fileName]; there {
				etag := RegBundles.Bundles[fileName].Etag
				w.Header().Set("ETag", etag)
				w.Header().Set(HeaderContentType, ContentTypeGzip)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Log.Debugf("HTTP request URI: %s, HTTP request headers: %+v", r.RequestURI, r.Header)
		next.ServeHTTP(w, r)
	})
}

func NoListMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), SC.Bundles.BundleUri) {
			path := r.URL.Path
			if strings.HasSuffix(path, "/") {
				log.Log.Debugf("Stopped dir listing, %s", path)
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(PageNotFound))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func parseJwt(in string, path string) (bool, error) {
	token, err := jwt.ParseNoVerify([]byte(in))
	if err != nil {
		return false, err
	}

	// create a Verifier (HMAC in this example)
	for _, s := range AD.Allowed {
		key := []byte(s.Secret)

		verifier, ve := jwt.NewVerifierHS(jwt.HS256, key)
		if ve != nil {
			log.Log.Debug("AuthZ failed to create verifier")
			//return false, err
			continue
		}

		// parse and verify a token
		tokenBytes := token.Bytes()
		newToken, pe := jwt.Parse(tokenBytes, verifier)
		if pe != nil {
			log.Log.Debugf("AuthZ failed to parse, ID=%s", s.ID)
			continue
		}

		// get Registered claims
		var claims jwt.RegisteredClaims
		errClaims := json.Unmarshal(newToken.Claims(), &claims)
		if errClaims != nil {
			log.Log.Debugf("AuthZ failed to get claims: %s", s.ID)
			//return false, errClaims
			continue
		}

		// verify claims as you wish
		audClaim := claims.IsForAudience(s.Audience)
		timeClaim := claims.IsValidAt(time.Now())

		if !audClaim || !timeClaim {
			log.Log.Debugf("AuthZ claims failure: audience claim valid: %t, Time claim valid: %t, ID: %s",
				audClaim, timeClaim, s.ID)

			//return false, errors.New("invalid JWT claims")
			continue
		} else {
			for _, e := range s.Entitlements {
				//fmt.Println("Path: " + path + ", Entitlement: " + e)
				if strings.Contains(path, e) {
					log.Log.Debugf("AuthZ succeeded with ID=%s", s.ID)
					return true, nil
				}
			}

			return false, nil
		}
	}

	return false, nil
}
