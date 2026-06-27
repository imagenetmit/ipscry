//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const ipSuccess = 0

var (
	icmpDLL          = syscall.MustLoadDLL("icmp.dll")
	procIcmpCreate   = icmpDLL.MustFindProc("IcmpCreateFile")
	procIcmpClose    = icmpDLL.MustFindProc("IcmpCloseHandle")
	procIcmpSendEcho = icmpDLL.MustFindProc("IcmpSendEcho")
)

// pingHost sends one ICMP echo and returns round-trip time in milliseconds.
func pingHost(ctx context.Context, ip string, timeout time.Duration) (int64, bool) {
	if ctx.Err() != nil {
		return -1, false
	}
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return -1, false
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	handle, _, _ := procIcmpCreate.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return -1, false
	}
	defer procIcmpClose.Call(handle)

	destIP := uint32(parsed[0]) | uint32(parsed[1])<<8 | uint32(parsed[2])<<16 | uint32(parsed[3])<<24
	request := []byte("ipscry")
	reply := make([]byte, 32+len(request)+8)
	timeoutMS := uint32(timeout / time.Millisecond)
	if timeoutMS == 0 {
		timeoutMS = 1
	}

	ret, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(destIP),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(len(request)),
		0,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(timeoutMS),
	)
	if ret == 0 {
		return -1, false
	}
	if binary.LittleEndian.Uint32(reply[4:8]) != ipSuccess {
		return -1, false
	}
	return int64(binary.LittleEndian.Uint32(reply[8:12])), true
}
