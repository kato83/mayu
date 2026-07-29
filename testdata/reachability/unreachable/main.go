//go:build ignore

package main

import (
	"fmt"
	"net/http"
)

func main() {
	// Uses http.StatusOK which is a constant, not a vulnerable symbol.
	fmt.Println(http.StatusOK)
}
