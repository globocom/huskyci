// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package routes

import (
	"net/http"

	"encoding/base64"

	"github.com/globocom/huskyCI/api/auth"
	apiContext "github.com/globocom/huskyCI/api/context"
	"github.com/globocom/huskyCI/api/log"
	"github.com/globocom/huskyCI/api/types"
	"github.com/labstack/echo"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/mgo.v2"
)

// UpdateUser edits an user
func UpdateUser(c echo.Context) error {

	// step 1.1: valid JSON?
	attemptUser := types.User{}
	err := c.Bind(&attemptUser)
	if err != nil {
		log.Error("EditUser", "USER", 1024, err)
		reply := map[string]interface{}{"success": false, "error": "invalid user JSON"}
		return c.JSON(http.StatusBadRequest, reply)
	}

	// step 1.2: check mongoDB injection

	// step 2.1: password/user is empty?
	if attemptUser.Password == "" || attemptUser.Username == "" || attemptUser.NewPassword == "" {
		reply := map[string]interface{}{"success": false, "error": "passwords/username can not be empty"}
		return c.JSON(http.StatusBadRequest, reply)
	}

	// step 2.2: passwords match?
	if attemptUser.NewPassword != attemptUser.ConfirmNewPassword {
		reply := map[string]interface{}{"success": false, "error": "passwords do not match"}
		return c.JSON(http.StatusBadRequest, reply)
	}

	// step 3: user exists?
	userQuery := map[string]interface{}{"username": attemptUser.Username}
	user, err := apiContext.APIConfiguration.DBInstance.FindOneDBUser(userQuery)
	if err != nil {
		if err == mgo.ErrNotFound || err.Error() == "No data found" {
			reply := map[string]interface{}{"success": false, "error": "user not found"}
			return c.JSON(http.StatusNotFound, reply)
		}
		reply := map[string]interface{}{"success": false, "error": "internal error"}
		return c.JSON(http.StatusInternalServerError, reply)
	}

	// step 4: password is correct?
	hashFunction, isValid := auth.GetValidHashFunction(user.HashFunction)
	if !isValid {
		reply := map[string]interface{}{"success": false, "error": "invalid hash function"}
		return c.JSON(http.StatusInternalServerError, reply)
	}
	salt, err := base64.StdEncoding.DecodeString(user.Salt)
	if err != nil {
		reply := map[string]interface{}{"success": false, "error": "failed to update user data"}
		return c.JSON(http.StatusInternalServerError, reply)
	}
	hashedPass := pbkdf2.Key([]byte(attemptUser.Password), salt, user.Iterations, user.KeyLen, hashFunction)
	if base64.StdEncoding.EncodeToString(hashedPass) != user.Password {
		reply := map[string]interface{}{"success": false, "error": "unauthorized"}
		return c.JSON(http.StatusUnauthorized, reply)
	}

	// step 5.1: prepare new user struct to be updated
	newHashedPass := pbkdf2.Key([]byte(attemptUser.NewPassword), salt, user.Iterations, user.KeyLen, hashFunction)

	updatedUser := types.User{
		Username:     attemptUser.Username,
		Password:     base64.StdEncoding.EncodeToString(newHashedPass),
		Salt:         user.Salt,
		Iterations:   user.Iterations,
		KeyLen:       user.KeyLen,
		HashFunction: user.HashFunction,
	}

	// step 5.2: update user
	if err := apiContext.APIConfiguration.DBInstance.UpdateOneDBUser(userQuery, updatedUser); err != nil {
		if err == mgo.ErrNotFound || err.Error() == "No data found" {
			reply := map[string]interface{}{"success": false, "error": "user not found"}
			return c.JSON(http.StatusNotFound, reply)
		}
		reply := map[string]interface{}{"success": false, "error": "internal error"}
		return c.JSON(http.StatusInternalServerError, reply)
	}

	reply := map[string]interface{}{"success": true, "error": ""}
	return c.JSON(http.StatusCreated, reply)
}
