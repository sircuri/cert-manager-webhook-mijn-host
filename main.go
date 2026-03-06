package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

// GroupName is the API group name for this webhook solver.
var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		GroupName = "acme.mijn.host"
	}

	cmd.RunWebhookServer(GroupName, &solver{})
}
