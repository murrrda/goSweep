package main

import (
	"fmt"
	"net/http"
)

func helloWorldPage(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, "Hello, world!")
}

func main() {
    http.HandleFunc("/", helloWorldPage)
    err := http.ListenAndServe("", nil)
    if err != nil {
        fmt.Printf("%v\n", err)
    }
}
