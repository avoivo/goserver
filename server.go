package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/avoivo/goserver/stateToken"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	accessTokenIssuer   = "avoivo/goserver"
	accessTokenAudience = "go-server-web-client"
)

// generate keys with the following
// ssh-keygen -t rsa -b 4096 -f access-token.rsa
// openssl rsa -in access-token.rsa -pubout -outform PEM -out access-token.rsa.pub
// -or-
// openssl genrsa -out access-token.rsa keysize
// openssl rsa -in access-token.rsa -pubout > access-token.rsa.pub

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

var addr = flag.String("addr", ":9999", "The http server address")
var mainTempl = template.Must(template.ParseFiles("main.html"))
var signInTempl = template.Must(template.ParseFiles("signin.html"))

var mainPageData mainPage
var signInPageData signInPage
var googleSignInClientID, googleSignInClientSecret, googleSignInClientRedirectURI string

var googleOAuth2Config *oauth2.Config
var stateTokenManager stateToken.Manager

var (
	signinRoute               = "/signin"
	idtokenRoute              = "/idtoken"
	resourceRoute             = "/resource"
	googleSigninRoute         = "/google_signin"
	googleSigninCallbackRoute = "/google_signin_callback"
)

func main() {

	flag.Parse()

	r := mux.NewRouter()
	r.HandleFunc("/", mainHandler).Methods("GET")
	r.HandleFunc(signinRoute, signInHandler).Methods("GET")
	r.HandleFunc(idtokenRoute, idTokenHandler).Methods("POST")
	r.HandleFunc(resourceRoute, authorizationMiddleware(resourceHandler)).Methods("GET")

	r.HandleFunc(googleSigninRoute, googleSignInHandler).Methods("GET")
	r.HandleFunc(googleSigninCallbackRoute, googleSignInCallbackHandler).Methods("GET")

	err := http.ListenAndServe(*addr, r)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	mainTempl.Execute(w, mainPageData)
}

func signInHandler(w http.ResponseWriter, req *http.Request) {
	signInTempl.Execute(w, signInPageData)
}

// validates the idToken in the request body and if it is valid it responds with an access token
func idTokenHandler(w http.ResponseWriter, req *http.Request) {

	body, err := ioutil.ReadAll(req.Body)
	defer req.Body.Close()

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bodyAsString := string(body)

	if strings.HasPrefix(bodyAsString, "idtoken=") == false {
		http.Error(w, "invalid body request", http.StatusBadRequest)
		return
	}

	idToken := bodyAsString[8:len(bodyAsString)]

	valid, err := validateGoogleIDToken(idToken)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if !valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	accessJWT, err := generateAccessToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%v", accessJWT)
}

// example of a protected resource
func resourceHandler(w http.ResponseWriter, req *http.Request) {

	resource := resource{"hello from resource"}

	js, err := json.Marshal(resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func googleSignInHandler(w http.ResponseWriter, req *http.Request) {
	token, err := stateTokenManager.Generate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	url := googleOAuth2Config.AuthCodeURL(token)
	http.Redirect(w, req, url, http.StatusFound)

}

func googleSignInCallbackHandler(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()

	stateToken := req.FormValue("state")
	log.Printf("State token: %v", stateToken)

	if stateTokenIsValid, err := stateTokenManager.Verify(stateToken); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if !stateTokenIsValid {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	code := req.FormValue("code")
	log.Printf("Code: %v", code)

	// Exchange the received code for a token
	tok, err := googleOAuth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	log.Printf("Token: %v", tok)

	googleAccessToken := tok.AccessToken
	log.Printf("google access Token: %v", googleAccessToken)

	googleIDToken := tok.Extra("id_token")
	log.Printf("google id Token: %v", googleIDToken)

	client := googleOAuth2Config.Client(oauth2.NoContext, tok)
	log.Printf("Client: %v", client)

}

func validateGoogleIDToken(token string) (valid bool, err error) {
	valid = true

	validateURI := fmt.Sprintf("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=%v", token)

	resp, err := http.Get(validateURI)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("google return status code different then OK-200")
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return false, err
	}

	var data map[string]interface{}

	if err := json.Unmarshal(body, &data); err != nil {
		return false, err
	}

	if data["aud"].(string) != googleSignInClientID {
		return false, errors.New("invalid audience")
	}

	return
}

func generateAccessToken() (tokenString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": accessTokenIssuer,
		"aud": accessTokenAudience,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})

	tokenString, err = token.SignedString(signKey)

	return
}

func authorizationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")

		if len(authorizationHeader) == 0 {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}

		splitedAuthHead := strings.Split(authorizationHeader, " ")

		if len(splitedAuthHead) != 2 || splitedAuthHead[0] != "Bearer" {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}

		tokenString := splitedAuthHead[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return verifyKey, nil
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		if !token.Valid {
			http.Error(w, "invalid token", http.StatusForbidden)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			http.Error(w, "cannot parse claims", http.StatusInternalServerError)
			return
		}

		if claims["aud"] != accessTokenAudience {
			http.Error(w, "Invalid audience", http.StatusForbidden)
			return
		}

		if claims["iss"] != accessTokenIssuer {
			http.Error(w, "Invalid issuer", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)

	})
}

func init() {
	googleSignInClientID = os.Getenv("GOOGLE_SIGN_IN_CLIENT_ID")
	if len(googleSignInClientID) == 0 {
		panic("GOOGLE_SIGN_IN_CLIENT_ID env variable is empty")
	}

	googleSignInClientSecret = os.Getenv("GOOGLE_SIGN_IN_CLIENT_SECRET")
	if len(googleSignInClientSecret) == 0 {
		panic("GOOGLE_SIGN_IN_CLIENT_SECRET env variable is empty")
	}

	googleSignInClientRedirectURI = os.Getenv("GOOGLE_SIGN_IN_REDIRECT_URI")
	if len(googleSignInClientRedirectURI) == 0 {
		panic("GOOGLE_SIGN_IN_REDIRECT_URI env variable is empty")
	}

	accessTokenPrivateKey := os.Getenv("ACCESS_TOKEN_PRIVATE_KEY")
	if len(accessTokenPrivateKey) == 0 {
		panic("ACCESS_TOKEN_PRIVATE_KEY env variable is empty")
	}

	accessTokenPublicKey := os.Getenv("ACCESS_TOKEN_PUBLIC_KEY")
	if len(accessTokenPublicKey) == 0 {
		panic("ACCESS_TOKEN_PUBLIC_KEY env variable is empty")
	}

	stateTokenSecret := os.Getenv("STATE_TOKEN_SECRET")
	if len(stateTokenSecret) == 0 {
		panic("STATE_TOKEN_SECRET env variable is empty")
	}

	mainPageData = mainPage{commonPage: commonPage{"GoLang server – A general purpose backend server", "Hello from Golang server"}}
	signInPageData = signInPage{commonPage: commonPage{"Sign in", "Please login using the following providers"}, GoogleSignInClientID: googleSignInClientID}

	signBytes := []byte(accessTokenPrivateKey)

	var err error

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		panic(err)
	}

	verifyBytes := []byte(accessTokenPublicKey)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

	if err != nil {
		panic(err)
	}

	googleOAuth2Config = &oauth2.Config{
		ClientID:     googleSignInClientID,
		ClientSecret: googleSignInClientSecret,
		RedirectURL:  googleSignInClientRedirectURI,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"openid",
			"email",
			"profile",
		},
	}

	stateTokenManager, err = stateToken.New(stateTokenSecret)
	if err != nil {
		panic(err)
	}
}

type commonPage struct {
	Title       string
	MainMessage string
}

type mainPage struct {
	commonPage
}

type signInPage struct {
	commonPage
	GoogleSignInClientID string
}

type resource struct {
	Message string
}
