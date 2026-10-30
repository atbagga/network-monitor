package discovery

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDescriptionReportsRouterMakeAndModel(t *testing.T) {
	data := `<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
		<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
		<friendlyName>Home router</friendlyName><manufacturer>Example Networks</manufacturer>
		<modelName>HomeHub</modelName><modelNumber>123</modelNumber>
	</device></root>`
	details, err := parseDescription(strings.NewReader(data))
	if err != nil || details.Type != "Router" || details.Manufacturer != "Example Networks" ||
		details.Model != "HomeHub 123" || details.FriendlyName != "Home router" {
		t.Fatalf("unexpected UPnP description: %+v, %v", details, err)
	}
	for _, invalid := range []string{"not xml", "<root/>", "<root><device>"} {
		if _, err := parseDescription(strings.NewReader(invalid)); err == nil {
			t.Fatalf("invalid description accepted: %s", invalid)
		}
	}
}

func TestDescriptionURLsCannotEscapeAdvertisingDevice(t *testing.T) {
	sender := netip.MustParseAddr("192.168.1.1")
	if !validDescriptionURL("http://192.168.1.1:1900/device.xml", sender) {
		t.Fatal("valid local description was rejected")
	}
	for _, location := range []string{
		"http://169.254.169.254/metadata", "http://127.0.0.1/admin",
		"http://192.168.1.2/device.xml", "http://example.com/device.xml",
		"file:///private", "http://user:password@192.168.1.1/private",
		"http://[::1]/", "https://192.168.1.1/device.xml",
	} {
		if validDescriptionURL(location, sender) {
			t.Fatalf("untrusted description URL accepted: %s", location)
		}
	}
}
