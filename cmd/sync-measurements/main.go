// Command sync-measurements folds the Chutes measurement list into egress/policy.yaml; it is in no image.
package main

import (
	"context"
	"os"
	"time"

	"github.com/sealedin/gateway/internal/measurements"
)

func main() {
	os.Exit(measurements.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, time.Now))
}
