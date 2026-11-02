package main

import (
	"context"
	"flag"
	"log"

	"github.com/Arequ/mission-control/terraform-provider-missioncontrol/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var version = "0.1.0"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/arequ/missioncontrol",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
