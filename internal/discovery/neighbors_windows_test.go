package discovery

import "testing"

func TestParseNeighbors(t *testing.T) {
	tests := []struct {
		name string
		json string
		want int
	}{
		{"empty", "", 0},
		{"null", "null", 0},
		{"single", `{"IPAddress":"192.168.1.1","LinkLayerAddress":"AA-BB-CC-DD-EE-02"}`, 1},
		{"filtered", `[
			{"IPAddress":"192.168.1.1","LinkLayerAddress":"AA-BB-CC-DD-EE-02"},
			{"IPAddress":"192.168.1.2","LinkLayerAddress":"00-00-00-00-00-00"},
			{"IPAddress":"192.168.1.3","LinkLayerAddress":"FF-FF-FF-FF-FF-FF"},
			{"IPAddress":"224.0.0.251","LinkLayerAddress":"01-00-5E-00-00-FB"},
			{"IPAddress":"192.168.1.4","LinkLayerAddress":"not-a-mac"}
		]`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseNeighbors([]byte(tt.json))
			if err != nil || len(result) != tt.want {
				t.Fatalf("got %v, %v; want %d devices", result, err, tt.want)
			}
			if len(result) > 0 && result[0].MAC != "aa:bb:cc:dd:ee:02" {
				t.Fatalf("MAC was not normalized: %s", result[0].MAC)
			}
		})
	}
	if _, err := parseNeighbors([]byte("not json")); err == nil {
		t.Fatal("expected malformed neighbor data to fail")
	}
}

func TestPingReplyRequiresTTL(t *testing.T) {
	if ttlReply.MatchString("Reply from 192.168.1.1: Destination host unreachable.") {
		t.Fatal("unreachable response must not be a positive discovery")
	}
	if !ttlReply.MatchString("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64") {
		t.Fatal("expected actual echo reply to be recognized")
	}
}
