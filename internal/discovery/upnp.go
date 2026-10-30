package discovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type upnpDevice struct {
	Type         string       `xml:"deviceType"`
	FriendlyName string       `xml:"friendlyName"`
	Manufacturer string       `xml:"manufacturer"`
	ModelName    string       `xml:"modelName"`
	ModelNumber  string       `xml:"modelNumber"`
	Children     []upnpDevice `xml:"deviceList>device"`
}

func discoverUPnP(ctx context.Context, network Network) ([]Observation, error) {
	prefix, err := netip.ParsePrefix(network.ScanCIDR)
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(network.Address)})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	request := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
	if _, err := connection.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
		return nil, err
	}
	connection.SetReadDeadline(time.Now().Add(1800 * time.Millisecond))
	locations := make(map[string]string)
	packet := make([]byte, 8192)
	for len(locations) < 32 {
		size, from, err := connection.ReadFromUDP(packet)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				break
			}
			return nil, err
		}
		ip, err := netip.ParseAddr(from.IP.String())
		if err != nil || !prefix.Contains(ip) {
			continue
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(packet[:size])), nil)
		if err != nil {
			continue
		}
		location := response.Header.Get("Location")
		response.Body.Close()
		if response.StatusCode == http.StatusOK && validDescriptionURL(location, ip) {
			locations[ip.String()] = location
		}
	}
	devices := make([]Observation, 0)
	var mutex sync.Mutex
	var workers sync.WaitGroup
	jobs := make(chan Observation)
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 800 * time.Millisecond,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(network.Address)}}).DialContext,
		DisableKeepAlives: true, MaxResponseHeaderBytes: 16 * 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for device := range jobs {
				details, err := fetchDescription(ctx, client, locations[device.IP])
				if err != nil {
					continue
				}
				device.Details = details
				mutex.Lock()
				devices = append(devices, device)
				mutex.Unlock()
			}
		}()
	}
	for ip := range locations {
		jobs <- Observation{IP: ip, Source: "UPnP advertisement"}
	}
	close(jobs)
	workers.Wait()
	return devices, nil
}

func validDescriptionURL(location string, sender netip.Addr) bool {
	parsed, err := url.Parse(location)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil {
		return false
	}
	host, err := netip.ParseAddr(parsed.Hostname())
	// Advertised URLs are untrusted: never resolve names, follow redirects or
	// fetch a different host (including cloud metadata and localhost).
	return err == nil && host.Is4() && host.IsPrivate() && host == sender
}

func fetchDescription(ctx context.Context, client *http.Client, location string) (Details, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return Details{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return Details{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Details{}, errors.New("device description was not returned")
	}
	return parseDescription(io.LimitReader(response.Body, 256*1024))
}

func parseDescription(reader io.Reader) (Details, error) {
	var root struct {
		Device upnpDevice `xml:"device"`
	}
	if err := xml.NewDecoder(reader).Decode(&root); err != nil {
		return Details{}, err
	}
	device := root.Device
	if device.Type == "" && device.FriendlyName == "" && device.Manufacturer == "" && device.ModelName == "" {
		return Details{}, errors.New("no UPnP device description found")
	}
	details := Details{FriendlyName: shortText(device.FriendlyName), Manufacturer: shortText(device.Manufacturer),
		Model:      shortText(strings.TrimSpace(device.ModelName + " " + device.ModelNumber)),
		ReportedAt: time.Now().UTC().Format(time.RFC3339), Evidence: []string{"UPnP device description (self-reported)"}}
	details.Type = upnpType(device)
	if details.Type != "" {
		details.TypeEvidence = "UPnP device type (self-reported)"
	}
	return details, nil
}

func upnpType(device upnpDevice) string {
	switch {
	case strings.Contains(device.Type, ":InternetGatewayDevice:"), strings.Contains(device.Type, ":WANDevice:"):
		return "Router"
	case strings.Contains(device.Type, ":Printer:"):
		return "Printer"
	case strings.Contains(device.Type, ":MediaRenderer:"), strings.Contains(device.Type, ":MediaServer:"):
		return "Media device"
	}
	for _, child := range device.Children {
		if kind := upnpType(child); kind != "" {
			return kind
		}
	}
	return ""
}

func shortText(value string) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > 160 {
		value = string(runes[:160])
	}
	return value
}
