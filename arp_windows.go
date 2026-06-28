//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

const (
	mibIPNetTypeDynamic = 3
	mibIPNetTypeStatic  = 4
)

type mibIPNetRow struct {
	dwIndex       uint32
	dwPhysAddrLen uint32
	bPhysAddr     [8]byte
	dwAddr        uint32
	dwType        uint32
}

var procGetIpNetTable = iphlpapi.MustFindProc("GetIpNetTable")

// arpCacheEntries returns IPv4 neighbors from the OS ARP table (dynamic cache
// entries and static mappings).
func arpCacheEntries() []arpCacheEntry {
	var size uint32
	ret, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 && ret != 122 { // ERROR_INSUFFICIENT_BUFFER
		return nil
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	ret, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // sort
	)
	if ret != 0 {
		return nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	var entries []arpCacheEntry
	offset := uintptr(4)
	for i := uint32(0); i < numEntries; i++ {
		if int(offset)+int(rowSize) > len(buf) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		switch row.dwType {
		case mibIPNetTypeDynamic, mibIPNetTypeStatic:
		default:
			continue
		}

		mac := physAddrToMAC(row.bPhysAddr[:], row.dwPhysAddrLen)
		if mac == "" {
			continue
		}
		entries = append(entries, arpCacheEntry{
			IP:      dwordToIPv4(row.dwAddr),
			MAC:     mac,
			Kind:    arpTypeName(row.dwType),
			IfIndex: row.dwIndex,
			IfAlias: interfaceAlias(row.dwIndex),
		})
	}
	return entries
}

func dwordToIPv4(d uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(d), byte(d>>8), byte(d>>16), byte(d>>24))
}

func physAddrToMAC(b []byte, length uint32) string {
	if length < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func arpTypeName(t uint32) string {
	switch t {
	case mibIPNetTypeDynamic:
		return "dynamic"
	case mibIPNetTypeStatic:
		return "static"
	case 2:
		return "invalid"
	default:
		return "other"
	}
}

func interfaceAlias(ifIndex uint32) string {
	if ifIndex == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return ""
	}
	return iface.Name
}
