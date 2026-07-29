//go:build ignore

package main

import (
	"fmt"
	nethttp "net/http"
)

func main() {
	resp, err := nethttp.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
