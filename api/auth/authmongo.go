// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/sha3"
)

// GetPassFromDB will search for a valid user entry in DB through the
// received username. It will set all parameters required for PBKDF's
// hash generation and return the hash password stored.
func (cM *ClientPbkdf2) GetPassFromDB(username string) (string, error) {
	userCreds, err := cM.HashGen.GetCredsFromDB(username)
	if err != nil {
		return "", err
	}
	cM.HashFunction = userCreds.HashFunction
	cM.Iterations = userCreds.Iterations
	cM.KeyLen = userCreds.KeyLen
	cM.Salt = userCreds.Salt
	return userCreds.Password, nil
}

// GetValidHashFunction is an auxiliary function called by GetHashedPass.
// It will return a valid hash function and a boolean if the hash was returned
// with success.
func GetValidHashFunction(hashStr string) (func() hash.Hash, bool) {
	hashLower := strings.ToLower(hashStr)
	var hashFunction func() hash.Hash
	var isValid bool
	switch hashLower {
	case "sha256":
		hashFunction = sha256.New
		isValid = true
	case "sha224":
		hashFunction = sha256.New224
		isValid = true
	case "sha384":
		hashFunction = sha512.New384
		isValid = true
	case "sha512":
		hashFunction = sha512.New
		isValid = true
	case "sha3_224":
		hashFunction = sha3.New224
		isValid = true
	case "sha3_256":
		hashFunction = sha3.New256
		isValid = true
	case "sha3_384":
		hashFunction = sha3.New384
		isValid = true
	case "sha3_512":
		hashFunction = sha3.New512
		isValid = true
	default:
		isValid = false
	}
	return hashFunction, isValid
}

// GetHashedPass will return the hash value of given password based
// on the parameters set by GetPassFromDB. It will verify first if
// all parameters required are valid.
func (cM *ClientPbkdf2) GetHashedPass(password string) (string, error) {
	hashFunction, isValid := GetValidHashFunction(cM.HashFunction)
	if cM.Salt == "" || cM.Iterations == 0 || cM.KeyLen == 0 || !isValid {
		return "", errors.New("Failed to generate a hash! It doesn't meet all criteria")
	}
	salt, err := cM.HashGen.DecodeSaltValue(cM.Salt)
	if err != nil {
		return "", err
	}
	return cM.HashGen.GenHashValue([]byte(password), salt, cM.Iterations, cM.KeyLen, hashFunction), nil
}
