package discovery

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func discoverMDNS(ctx context.Context, network Network) ([]Observation, error) {
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
	connection.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	destination := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	queried := make(map[string]bool)
	query := func(name string, kind dnsmessage.Type) error {
		key := name + kind.String()
		if queried[key] || len(queried) >= 64 {
			return nil
		}
		parsed, err := dnsmessage.NewName(name)
		if err != nil {
			return err
		}
		queried[key] = true
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: 1},
			Questions: []dnsmessage.Question{{Name: parsed, Type: kind, Class: dnsmessage.ClassINET | 0x8000}}}
		packet, err := message.Pack()
		if err != nil {
			return err
		}
		_, err = connection.WriteToUDP(packet, destination)
		return err
	}
	for _, service := range []string{"_device-info._tcp.local.", "_workstation._tcp.local.",
		"_ipp._tcp.local.", "_ipps._tcp.local.", "_airplay._tcp.local.", "_googlecast._tcp.local.",
		"_companion-link._tcp.local.", "_androidtvremote2._tcp.local."} {
		if err := query(service, dnsmessage.TypePTR); err != nil {
			return nil, err
		}
	}
	reports := make(map[string]Observation)
	targets := make(map[string]string)
	addresses := make(map[string]string)
	packet := make([]byte, 9000)
	for packets := 0; packets < 256; packets++ {
		size, sender, err := connection.ReadFromUDP(packet)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				break
			}
			return nil, err
		}
		ip, err := netip.ParseAddr(sender.IP.String())
		if err != nil || !prefix.Contains(ip) {
			continue
		}
		var message dnsmessage.Message
		if err := message.Unpack(packet[:size]); err != nil || !message.Response {
			continue
		}
		for _, record := range append(message.Answers, message.Additionals...) {
			name := record.Header.Name.String()
			switch body := record.Body.(type) {
			case *dnsmessage.PTRResource:
				if supportedMDNSService(name) {
					_ = query(body.PTR.String(), dnsmessage.TypeALL)
				}
			case *dnsmessage.SRVResource:
				if supportedMDNSService(name) {
					targets[name] = body.Target.String()
					_ = query(body.Target.String(), dnsmessage.TypeA)
					device := reports[name]
					device.IP, device.Source = ip.String(), "mDNS advertisement"
					device.Hostname = strings.TrimSuffix(body.Target.String(), ".")
					device.Details = MergeDetails(device.Details, mdnsDetails(name, nil))
					reports[name] = device
				}
			case *dnsmessage.TXTResource:
				if supportedMDNSService(name) {
					device := reports[name]
					device.IP, device.Source = ip.String(), "mDNS advertisement"
					device.Details = MergeDetails(device.Details, mdnsDetails(name, body.TXT))
					reports[name] = device
				}
			case *dnsmessage.AResource:
				address := netip.AddrFrom4(body.A)
				if prefix.Contains(address) {
					addresses[name] = address.String()
				}
			}
		}
	}
	devices := make([]Observation, 0, len(reports))
	for instance, device := range reports {
		if address := addresses[targets[instance]]; address != "" {
			device.IP = address
		}
		if device.IP != "" {
			devices = append(devices, device)
		}
	}
	return devices, nil
}

func supportedMDNSService(name string) bool {
	name = strings.ToLower(name)
	for _, service := range []string{"_device-info.", "_workstation.", "_ipp.", "_ipps.", "_airplay.",
		"_googlecast.", "_companion-link.", "_androidtvremote2."} {
		if strings.Contains(name, service) {
			return true
		}
	}
	return false
}

func mdnsDetails(instance string, records []string) Details {
	values := make(map[string]string)
	for _, record := range records {
		key, value, ok := strings.Cut(record, "=")
		if ok {
			values[strings.ToLower(key)] = shortText(value)
		}
	}
	first := func(keys ...string) string {
		for _, key := range keys {
			if values[key] != "" {
				return values[key]
			}
		}
		return ""
	}
	details := Details{Model: first("model", "md", "usb_mdl", "ty", "product"),
		Manufacturer: first("manufacturer", "usb_mfg", "mfg"), FriendlyName: first("fn", "name"),
		ReportedAt: time.Now().UTC().Format(time.RFC3339),
		Evidence:   []string{"mDNS/DNS-SD advertisement (self-reported)"}}
	name := strings.ToLower(instance)
	switch {
	case strings.Contains(name, "._ipp."), strings.Contains(name, "._ipps."):
		details.Type = "Printer"
	case strings.Contains(name, "._googlecast."), strings.Contains(name, "._airplay."):
		details.Type = "Media device"
	case strings.Contains(name, "._androidtvremote2."):
		details.Type = "Television"
	case strings.Contains(name, "._workstation."):
		details.Type = "Computer"
	}
	model := strings.ToLower(details.Model)
	switch {
	case strings.HasPrefix(model, "iphone"):
		details.Type, details.Manufacturer = "Phone", "Apple"
	case strings.HasPrefix(model, "ipad"):
		details.Type, details.Manufacturer = "Tablet", "Apple"
	case strings.HasPrefix(model, "macbook"), strings.HasPrefix(model, "imac"),
		strings.HasPrefix(model, "macmini"), strings.HasPrefix(model, "macpro"):
		details.Type, details.Manufacturer = "Computer", "Apple"
	case strings.HasPrefix(model, "appletv"):
		details.Type, details.Manufacturer = "Media device", "Apple"
	}
	if details.Type != "" {
		details.TypeEvidence = "mDNS service (self-reported)"
		if strings.HasPrefix(model, "iphone") || strings.HasPrefix(model, "ipad") ||
			strings.HasPrefix(model, "macbook") || strings.HasPrefix(model, "imac") ||
			strings.HasPrefix(model, "macmini") || strings.HasPrefix(model, "macpro") ||
			strings.HasPrefix(model, "appletv") {
			details.TypeEvidence = "mDNS model identifier (self-reported)"
		}
	}
	return details
}
