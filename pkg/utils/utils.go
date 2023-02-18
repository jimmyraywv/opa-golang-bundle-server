package utils

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
	log "jimmyray.io/opa-bundle-api/pkg/logging"
)

// Namespacing functions with structs, overcoming the lack of overloading

type strng struct{}
type intgr struct{}

func (z strng) ArrayContains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

var Strng strng

func (z intgr) ArrayContains(a []int, i int) bool {
	for _, x := range a {
		if x == i {
			return true
		}
	}
	return false
}

var Intgr intgr

func ArrayContains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func MD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func FileInfos(path string) (map[string]os.FileInfo, error) {
	m := make(map[string]os.FileInfo)
	err := filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			m[path] = info
			return nil
		})
	if err != nil {
		return m, err
	}

	return m, nil
}

func TsString() string {
	now := time.Now() // current local time
	sec := now.Unix()

	return strconv.FormatInt(sec, 10)
}

func WriteFile(path string, bytes []byte) error {
	var i int
	if _, err := os.Stat(path); err == nil {
		f, e := os.Open(path)
		defer f.Close()
		if e == nil {
			i, e = f.Write(bytes)
			if e != nil {
				return e
			}

			log.Log.Debugf("wrote %d bytes to %s", i, path)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		f, e := os.Create(path)
		defer f.Close()
		if e == nil {
			i, e = f.Write(bytes)
		}
		if e != nil {
			return e
		}

		log.Log.Debugf("wrote %d bytes to %s", i, path)
	} else {
		return err
	}

	return nil
}

func ReadFile(path string) ([]byte, error) {
	var bytes []byte
	var err error
	var fi fs.FileInfo

	fi, err = os.Stat(path) //};  errors.Is(err, os.ErrNotExist) {
	if fi != nil && err == nil {
		log.Log.Debugf("File info: %+v", fi)
	} else {
		log.Log.Errorf("File info issues: %+v", err)
	}

	// Read file
	bytes, err = os.ReadFile(path)
	if err != nil {
		return bytes, err
	}

	return bytes, nil
}

func FileExists(fileName string) bool {
	_, err := os.Stat(fileName)

	// check if error is "file not exists"
	if os.IsNotExist(err) {
		return false
	}
	return true

}
