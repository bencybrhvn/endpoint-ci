//go:build !(js && wasm)

// Native stub so `go build ./...` / `go vet ./...` don't fail on this package
// outside a WASM build. The real entrypoint is main.go (js && wasm).
package main

import "fmt"

func main() {
	fmt.Println("build for the browser with: GOOS=js GOARCH=wasm go build -o web/ch.wasm ./cmd/wasm")
}
