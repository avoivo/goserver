package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
)

var addr = flag.String("addr", ":9999", "The http server address")
var templ = template.Must(template.ParseFiles("main.html"))
var mainPageData mainPage

func main() {
	flag.Parse()
	http.Handle("/", http.HandlerFunc(mainHandler))
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	templ.Execute(w, mainPageData)
}

func init() {
	mainPageData = mainPage{"GoLang server – A general purpose backend server", "Hello from Golang server"}
}

type mainPage struct {
	Title       string
	MainMessage string
}
