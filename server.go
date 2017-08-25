package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
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
	err := http.ListenAndServe(*addr, nil)
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
