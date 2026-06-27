//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	enableVirtualTerminalProcessing = 0x0004
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableVirtualTerminalInput      = 0x0200
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

func enableVTMode(w *os.File) error {
	handle := syscall.Handle(w.Fd())
	var mode uint32
	r, _, err := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return err
	}
	mode |= enableVirtualTerminalProcessing
	r, _, err = procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	if r == 0 {
		return err
	}
	return nil
}

func isTerminal(f *os.File) bool {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(f.Fd(), uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

// enableRawMode switches the console input handle to cbreak mode (line input and
// echo disabled) so single keystrokes are delivered immediately, and turns on
// ENABLE_VIRTUAL_TERMINAL_INPUT so the arrow / Page / Home / End keys arrive as
// ANSI escape sequences that readKey can decode (without it, Windows consoles —
// including remote web terminals — never deliver those keys as readable bytes).
// ENABLE_PROCESSED_INPUT is left untouched so Ctrl+C still raises an interrupt.
// If the console rejects VT input we retry without it so plain keys still work.
// The returned restore func reverts the original mode and is always safe to call.
func enableRawMode(f *os.File) (restore func(), raw bool) {
	handle := f.Fd()
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return func() {}, false
	}
	restoreFn := func() { procSetConsoleMode.Call(handle, uintptr(mode)) }
	base := mode &^ uint32(enableLineInput|enableEchoInput)
	if r, _, _ := procSetConsoleMode.Call(handle, uintptr(base|enableVirtualTerminalInput)); r != 0 {
		return restoreFn, true
	}
	if r, _, _ := procSetConsoleMode.Call(handle, uintptr(base)); r != 0 {
		return restoreFn, true
	}
	return func() {}, false
}

func consoleSize(fd uintptr) (cols, rows int) {
	type coord struct {
		x int16
		y int16
	}
	type smallRect struct {
		left, top, right, bottom int16
	}
	type csbi struct {
		size          coord
		cursor        coord
		attributes    uint16
		window        smallRect
		maxWindowSize coord
	}
	var info csbi
	procGetCSBI := kernel32.NewProc("GetConsoleScreenBufferInfo")
	handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return 80, 24
	}
	r, _, _ := procGetCSBI.Call(uintptr(handle), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return 80, 24
	}
	w := int(info.window.right - info.window.left + 1)
	h := int(info.window.bottom - info.window.top + 1)
	if w < 40 {
		w = 80
	}
	if h < 10 {
		h = 24
	}
	return w, h
}
