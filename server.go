package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
)

var addr = flag.String("addr", ":9999", "The http server address")
var templ = template.Must(template.New("main").Parse(htmlTemplate))

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

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>GoLang server – A general purpose backend server</title>
</head>

<body>
	<h1>Hello from Golang server</h1>
</body>
</html>`
