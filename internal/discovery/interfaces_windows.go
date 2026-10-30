package discovery

import (
	"encoding/binary"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wlanDLL = windows.NewLazySystemDLL("wlanapi.dll")
var wlanOpen = wlanDLL.NewProc("WlanOpenHandle")
var wlanQuery = wlanDLL.NewProc("WlanQueryInterface")
var wlanFree = wlanDLL.NewProc("WlanFreeMemory")
var wlanClose = wlanDLL.NewProc("WlanCloseHandle")

func platformInterfaces() map[int]interfaceDetails {
	result := make(map[int]interfaceDetails)
	size := uint32(15000)
	var buffer []byte
	var head *windows.IpAdapterAddresses
	loaded := false
	for attempts := 0; attempts < 3; attempts++ {
		buffer = make([]byte, size)
		head = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, head, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return result
		}
		loaded = true
		break
	}
	if !loaded {
		return result
	}
	var handle windows.Handle
	var negotiated uint32
	if wlanOpen.Find() == nil {
		code, _, _ := wlanOpen.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
		if code == 0 {
			defer wlanClose.Call(uintptr(handle), 0)
		} else {
			handle = 0
		}
	}
	for adapter := head; adapter != nil; adapter = adapter.Next {
		info := interfaceDetails{}
		info.AdapterModel = windows.UTF16PtrToString(adapter.Description)
		if adapter.NetworkGuid != (windows.GUID{}) {
			info.Key = adapter.NetworkGuid.String()
		}
		if handle != 0 && adapter.IfType == 71 {
			guid, err := windows.GUIDFromString(windows.BytePtrToString(adapter.AdapterName))
			if err == nil {
				info.Profile = wifiSSID(handle, guid)
				if info.Profile != "" {
					info.Key = "wifi:" + info.Profile
				}
			}
		}
		for gateway := adapter.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
			ip := gateway.Address.IP()
			if ip != nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.Equal(net.IPv4zero) {
				info.Gateway = ip.String()
				break
			}
		}
		result[int(adapter.IfIndex)] = info
	}
	runtime.KeepAlive(buffer)
	return result
}

func wifiSSID(handle windows.Handle, guid windows.GUID) string {
	var size uint32
	var data unsafe.Pointer
	// WLAN_CONNECTION_ATTRIBUTES begins with state, mode, a 256-WCHAR profile
	// name, then DOT11_SSID. Never interpret the remaining native structure.
	code, _, _ := wlanQuery.Call(uintptr(handle), uintptr(unsafe.Pointer(&guid)), 7, 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
	if code != 0 || data == nil {
		return ""
	}
	defer wlanFree.Call(uintptr(data))
	if size < 556 {
		return ""
	}
	bytes := unsafe.Slice((*byte)(data), 556)
	length := binary.LittleEndian.Uint32(bytes[520:524])
	if length == 0 || length > 32 {
		return ""
	}
	return string(bytes[524 : 524+length])
}
