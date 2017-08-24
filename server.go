package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

var addr = flag.String("addr", ":9999", "The http server address")

func main() {
	flag.Parse()
	http.Handle("/", http.HandlerFunc(mainHandler))
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello there")
}
