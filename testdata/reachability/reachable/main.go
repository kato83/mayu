//go:build ignore

package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
