package model

import (
	"encoding/json"
	"github.com/cristalhq/jwt/v4"
	"jimmyray.io/opa-bundle-api/pkg/utils"
	"net/http"
	"path"
	"strings"
	"time"
)

type AuthzData struct {
	Allowed []struct {
		ID       string `json:"id"`
		Secret   string `json:"secret"`
		Audience string `json:"audience"`
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
		utils.Logger.Errorf("could not unmarshal JSON: %+v", err)
		return err
	}

	s, _ := AD.Json()
	utils.Logger.Debugf("AuthZ JSON: %s", s)
	return nil
}

func AuthZMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var header = r.Header.Get("Authorization")
		header = strings.TrimSpace(header)

		if len(header) <= 7 {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(Forbidden))
			return
		}

		token := header[7:]

		valid, err := parseJwt(token)
		if err != nil {
			errorData := utils.ErrorLog{Skip: 1, Event: "JWT parsing", Message: err.Error()}
			utils.LogErrors(errorData)

			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(Forbidden))
			return
		}

		if !valid {
			utils.Logger.Debug("Invalid JWT")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(Forbidden))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func EtagMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileName := path.Base(r.URL.String())
		if _, there := RegBundles.Bundles[fileName]; there {
			etag := RegBundles.Bundles[fileName].Etag
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Content-Type", "application/gzip")
		next.ServeHTTP(w, r)
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.Logger.Debugf("HTTP request URI: %s, HTTP request headers: %+v", r.RequestURI, r.Header)
		next.ServeHTTP(w, r)
	})
}

func NoListMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/") {
			utils.Logger.Debugf("Stopped dir listing, %s", path)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(PageNotFound))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func parseJwt(in string) (bool, error) {
	token, err := jwt.ParseNoVerify([]byte(in))
	if err != nil {
		return false, err
	}

	// create a Verifier (HMAC in this example)
	for _, s := range AD.Allowed {
		key := []byte(s.Secret)

		verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
		if err != nil {
			utils.Logger.Debug("Failed to create verifier")
			//return false, err
			continue
		}

		// parse and verify a token
		tokenBytes := token.Bytes()
		newToken, err := jwt.Parse(tokenBytes, verifier)
		if err != nil {
			utils.Logger.Debugf("Failed to parse, ID: %s", s.ID)
			continue
		}

		// or just verify it's signature
		//err = verifier.Verify(newToken)
		//if err != nil {
		//	utils.Logger.Debug("Failed to verify signature")
		//	return false, err
		//}

		// get Registered claims
		var claims jwt.RegisteredClaims
		errClaims := json.Unmarshal(newToken.Claims(), &claims)
		if errClaims != nil {
			utils.Logger.Debugf("Failed to get claims: %s", s.ID)
			//return false, errClaims
			continue
		}

		// or parse only claims
		//errParseClaims := jwt.ParseClaims(tokenBytes, verifier, &newClaims)
		//if errParseClaims != nil {
		//	utils.Logger.Debug("Failed to parse claims")
		//	return false, errParseClaims
		//}

		// verify claims as you wish
		audClaim := claims.IsForAudience(s.Audience)
		timeClaim := claims.IsValidAt(time.Now())

		if !audClaim || !timeClaim {
			utils.Logger.Debugf("Audience claim valid: %t, Time claim valid: %t, ID: %s", audClaim, timeClaim, s.ID)

			//return false, errors.New("invalid JWT claims")
			continue
		} else {
			utils.Logger.Debugf("AuthZ succeeded with ID=%s", s.ID)
			return true, nil
		}
	}

	return false, nil
}