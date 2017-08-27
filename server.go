package main

import (
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

	"github.com/dgrijalva/jwt-go"
)

const (
	accessTokenIssuer   = "avoivo/goserver"
	accessTokenAudience = "go-server-web-client"
)

// location of the files used for signing and verification
// ssh-keygen -t rsa -b 4096 -f access-token.rsa
// openssl rsa -in access-token.rsa -pubout -outform PEM -out access-token.rsa.pub
// -or-
// openssl genrsa -out access-token.rsa keysize
// openssl rsa -in access-token.rsa -pubout > access-token.rsa.pub

const (
	privKeyPath = "keys/access-token.rsa"
	pubKeyPath  = "keys/access-token.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

var addr = flag.String("addr", ":9999", "The http server address")
var mainTempl = template.Must(template.ParseFiles("main.html"))
var signInTempl = template.Must(template.ParseFiles("signin.html"))

var mainPageData mainPage
var signInPageData signInPage
var googleSignInClientID string

func main() {

	flag.Parse()
	http.Handle("/", http.HandlerFunc(mainHandler))
	http.Handle("/signin", http.HandlerFunc(signInHandler))
	http.Handle("/idtoken", http.HandlerFunc(idTokenHandler))
	http.Handle("/resource", authorizationMiddleware(http.HandlerFunc(resourceHandler)))

	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	mainTempl.Execute(w, mainPageData)
}

func signInHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	signInTempl.Execute(w, signInPageData)
}

// validates the idToken in the request body and if it is valid it responds with an access token
func idTokenHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

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
	if req.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	resource := resource{"hello from resource"}

	js, err := json.Marshal(resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
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

func authorizationMiddleware(next http.Handler) http.Handler {
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

	mainPageData = mainPage{commonPage: commonPage{"GoLang server – A general purpose backend server", "Hello from Golang server"}}
	signInPageData = signInPage{commonPage: commonPage{"Sign in", "Please login using the following providers"}, GoogleSignInClientID: googleSignInClientID}

	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		panic(err)
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		panic(err)
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		panic(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

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
