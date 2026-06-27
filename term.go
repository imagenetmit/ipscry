package main

import (
	"io"
	"os"
)

const (
	escClear      = "\033[2J"
	escHome       = "\033[H"
	escClearLine  = "\033[K"
	escClearDown  = "\033[J"
	escAltScreen  = "\033[?1049h"
	escMainScreen = "\033[?1049l"
	escHideCursor = "\033[?25l"
	escShowCursor = "\033[?25h"
	escReset      = "\033[0m"
)

// Color/attribute SGR codes are vars so NO_COLOR can blank them at startup
// while leaving cursor/screen-control sequences intact.
var (
	escBold    = "\033[1m"
	escDim     = "\033[2m"
	escReverse = "\033[7m"
	escCyan    = "\033[36m"
	escGreen   = "\033[32m"
	escYellow  = "\033[33m"
	escRed     = "\033[31m"
)

func init() {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		escBold, escDim, escReverse = "", "", ""
		escCyan, escGreen, escYellow, escRed = "", "", "", ""
	}
}

func termColumnsRows(w io.Writer) (cols, rows int) {
	if f, ok := w.(interface{ Fd() uintptr }); ok {
		return consoleSize(f.Fd())
	}
	return 80, 24
}
