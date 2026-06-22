//go:build windows

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// iphlpapi.dll/SendARP is always present on Windows, so loading it eagerly is safe.
var (
	iphlpapi    = syscall.MustLoadDLL("iphlpapi.dll")
	procSendARP = iphlpapi.MustFindProc("SendARP")
)

// lookupMAC resolves the layer-2 address of a local-subnet IPv4 host via the
// Windows SendARP API. Returns "" for routed hosts (no ARP entry) or on error.
func lookupMAC(ip string) string {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return ""
	}
	// IPAddr (in_addr) stores the first octet in the least-significant byte.
	destIP := uint32(parsed[0]) | uint32(parsed[1])<<8 | uint32(parsed[2])<<16 | uint32(parsed[3])<<24

	var mac [8]byte
	macLen := uint32(len(mac))
	ret, _, _ := procSendARP.Call(
		uintptr(destIP),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 || macLen < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
