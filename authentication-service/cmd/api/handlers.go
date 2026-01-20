package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {

	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		log.Println("some message", err)
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	user, err := app.Models.User.GetByEmail(requestPayload.Email)
	if err != nil {
		log.Println("some message", err)
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}
	password := requestPayload.Password //"verysecret!"
	hash, _ := HashPassword(password)   // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)

	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
	valid, err := user.PasswordMatches(requestPayload.Password)
	if err != nil || !valid {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: fmt.Sprintf("logged in user %s", user.Email),
		Data:    user,
	}

	app.writeJSON(w, http.StatusAccepted, payload)
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
