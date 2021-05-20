// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"crypto/rand"
	"encoding/base64"
	"hash"
	"io"
	"os"
	"strconv"

	apiContext "github.com/globocom/huskyCI/api/context"
	"github.com/globocom/huskyCI/api/types"
	"golang.org/x/crypto/pbkdf2"
)

// GetCredsFromDB returns an user info given an username.
func (pC *Pbkdf2Caller) GetCredsFromDB(username string) (types.User, error) {
	searchParam := map[string]interface{}{"username": username}
	return apiContext.APIConfiguration.DBInstance.FindOneDBUser(searchParam)
}

// DecodeSaltValue decodes a salt and returns a string and an error.
func (pC *Pbkdf2Caller) DecodeSaltValue(salt string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(salt)
}

// GenHashValue returns the hash value given all pbkdf2 parameters.
func (pC *Pbkdf2Caller) GenHashValue(value, salt []byte, iter, keyLen int, hashFunc func() hash.Hash) string {
	return base64.StdEncoding.EncodeToString(pbkdf2.Key(value, salt, iter, keyLen, hashFunc))
}

// GenerateSalt returns a random salt and en error.
func (pC *Pbkdf2Caller) GenerateSalt() (string, error) {
	salt := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, salt)
	return base64.StdEncoding.EncodeToString(salt), err
}

// GetHashName returns the default hash name that is stored in an env var.
func (pC *Pbkdf2Caller) GetHashName() string {
	hashFunction := os.Getenv("HUSKYCI_API_DEFAULT_HASH_FUNCTION")
	if hashFunction != "" {
		return hashFunction
	}
	return "SHA512"
}

// GetIterations returns the default number of iteration that is stored in an env var.
func (pC *Pbkdf2Caller) GetIterations() int {
	rawIterations := os.Getenv("HUSKYCI_API_DEFAULT_ITERATIONS")
	if rawIterations != "" {
		iterations, err := strconv.Atoi(rawIterations)
		if err != nil {
			return 100000
		}
		return iterations
	}
	return 100000
}

// GetKeyLength returns the default key lenght that is stored in an env var.
func (pC *Pbkdf2Caller) GetKeyLength() int {
	rawKeyLength := os.Getenv("HUSKYCI_API_DEFAULT_KEY_LENGTH")
	if rawKeyLength != "" {
		keyLengh, err := strconv.Atoi(rawKeyLength)
		if err != nil {
			return 512
		}
		return keyLengh
	}
	return 512
}
