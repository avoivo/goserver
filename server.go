package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
)

var addr = flag.String("addr", ":9999", "The http server address")
var templ = template.Must(template.ParseFiles("main.html"))

func main() {
	flag.Parse()
	http.Handle("/", http.HandlerFunc(mainHandler))
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	templ.Execute(w, nil)
}
