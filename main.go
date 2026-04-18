package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func main() {
	gn := os.Getenv("GROUP_NAME")
	if gn == "" {
		gn = groupName
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := runWebhookServer(ctx, gn, &mijnHostSolver{}); err != nil {
		logf.Log.Error(err, "error running webhook server")
		os.Exit(1)
	}
}
