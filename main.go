package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

func main() {
	gn := os.Getenv("GROUP_NAME")
	if gn == "" {
		gn = groupName
	}

	cmd.RunWebhookServer(gn, &mijnHostSolver{})
}
