//go:build !windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func enableVTMode(*os.File) error {
	return nil
}

func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	return err == 0
}

// enableRawMode is a no-op on unix: we fall back to line-buffered input (the
// caller reads a whole line and acts on the first key, so the user must press
// Enter after the letter). Raw termios is intentionally avoided to keep the
// unix path simple and robust; single-key handling is prioritized on Windows.
func enableRawMode(*os.File) (restore func(), raw bool) {
	return func() {}, false
}

func consoleSize(fd uintptr) (cols, rows int) {
	type winsize struct {
		row, col       uint16
		xpixel, ypixel uint16
	}
	var ws winsize
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if err != 0 || ws.col == 0 || ws.row == 0 {
		return 80, 24
	}
	return int(ws.col), int(ws.row)
}
