package main

import (
	"fmt"
	"log"
	"net/http"

	"diffie-hellman-key-exchange/pkg/cache"
	"diffie-hellman-key-exchange/pkg/handler"
)

func main() {
	cc, err := cache.New()
	if err != nil {
		panic(err)
	}

	hdl := handler.New(cc)

	http.HandleFunc("/session", hdl.Session)

	http.HandleFunc("/password", hdl.Password)

	fmt.Println("Server Start Up........")

	log.Fatal(http.ListenAndServe("localhost:5555", nil))
}
