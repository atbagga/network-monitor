//go:build !windows

package discovery

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

func platformInterfaces() map[int]interfaceDetails {
	return nil
}

func ping(ctx context.Context, address string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	return exec.CommandContext(probeCtx, "ping", "-n", "-c", "1", "-W", "1", address).Run() == nil
}

func readNeighbors(context.Context, Network) ([]Observation, error) {
	return nil, errors.New("neighbor-table discovery currently supports Windows only; ICMP discovery remains available")
}
