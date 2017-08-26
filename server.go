package main

import (
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

	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	mainTempl.Execute(w, mainPageData)
}

func signInHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	signInTempl.Execute(w, signInPageData)
}

func idTokenHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
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

	log.Println("id token called")
	fmt.Fprintf(w, "this seems to work")
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

func init() {
	googleSignInClientID = os.Getenv("GOOGLE_SIGN_IN_CLIENT_ID")
	if len(googleSignInClientID) == 0 {
		panic("GOOGLE_SIGN_IN_CLIENT_ID env variable is empty")
	}

	mainPageData = mainPage{commonPage: commonPage{"GoLang server – A general purpose backend server", "Hello from Golang server"}}
	signInPageData = signInPage{commonPage: commonPage{"Sign in", "Please login using the following providers"}, GoogleSignInClientID: googleSignInClientID}
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
