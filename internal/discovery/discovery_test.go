package discovery

import (
	"context"
	"net/netip"
	"testing"
)

func TestTargetsBounds(t *testing.T) {
	tests := []struct {
		prefix string
		count  int
		first  string
		last   string
	}{
		{"192.168.1.42/24", 254, "192.168.1.1", "192.168.1.254"},
		{"10.0.0.1/30", 2, "10.0.0.1", "10.0.0.2"},
		{"10.0.0.4/31", 2, "10.0.0.4", "10.0.0.5"},
		{"172.16.0.8/32", 1, "172.16.0.8", "172.16.0.8"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			targets, err := Targets(netip.MustParsePrefix(tt.prefix))
			if err != nil {
				t.Fatal(err)
			}
			if len(targets) != tt.count || targets[0].String() != tt.first || targets[len(targets)-1].String() != tt.last {
				t.Fatalf("unexpected targets: %v", targets)
			}
		})
	}
	for _, prefix := range []string{"192.168.0.0/16", "8.8.8.0/24", "127.0.0.0/24", "fd00::/120"} {
		t.Run(prefix, func(t *testing.T) {
			if _, err := Targets(netip.MustParsePrefix(prefix)); err == nil {
				t.Fatal("expected invalid scope to be rejected")
			}
		})
	}
}

func TestScanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Scan(ctx, Network{ID: "1:192.168.1.0/24", ScanCIDR: "192.168.1.0/24"})
	if err != context.Canceled {
		t.Fatalf("got %v, want cancellation", err)
	}
}
