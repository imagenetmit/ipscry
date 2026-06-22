//go:build !windows

package main

// lookupMAC has no portable non-Windows implementation; ipscry is Windows-oriented
// and the ARP table is read via SendARP there. Other platforms get no MAC.
func lookupMAC(ip string) string {
	return ""
}
