package main

import (
	"os"

	"github.com/Arequ/mission-control/internal/fakeautopkg"
)

func main() {
	os.Exit(fakeautopkg.Main(os.Args[1:]))
}
