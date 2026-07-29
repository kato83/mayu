//go:build ignore

package main

import (
	"fmt"
	"net/http"
)

func main() {
	client := &http.Client{}
	resp, err := client.Do(nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
