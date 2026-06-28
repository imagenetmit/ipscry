package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/csv"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:generate go run tools/gendata/main.go

//go:embed data/ports.csv
var embeddedPortsCSV []byte

//go:embed data/mac_vendors.csv.gz
var embeddedMACVendorsGZ []byte

type portEntry struct {
	service string
	vendors string
}

var (
	portsByNumber    map[int]portEntry
	defaultScanPorts []int
)

var (
	macVendorsOnce sync.Once
	oui24          map[string]string // 6 hex (MA-L, CID)
	oui28          map[string]string // 7 hex (MA-M)
	oui36          map[string]string // 9 hex (MA-S, IAB)
)

func init() {
	portsByNumber = parsePortsCSV(embeddedPortsCSV)
	defaultScanPorts = sortedPortKeys(portsByNumber)
}

func sortedPortKeys(m map[int]portEntry) []int {
	ports := make([]int, 0, len(m))
	for port := range m {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func parsePortsCSV(data []byte) map[int]portEntry {
	out := map[int]portEntry{}
	r := csv.NewReader(bytes.NewReader(data))
	records, err := r.ReadAll()
	if err != nil {
		return out
	}
	for i, rec := range records {
		if i == 0 || len(rec) < 2 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(rec[0]))
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		entry := portEntry{service: strings.ToLower(strings.TrimSpace(rec[1]))}
		if len(rec) >= 3 {
			entry.vendors = strings.TrimSpace(rec[2])
		}
		out[port] = entry
	}
	return out
}

func initMACVendors() {
	oui24 = map[string]string{}
	oui28 = map[string]string{}
	oui36 = map[string]string{}

	gz, err := gzip.NewReader(bytes.NewReader(embeddedMACVendorsGZ))
	if err != nil {
		return
	}
	defer gz.Close()

	r := csv.NewReader(gz)
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if len(rec) < 2 {
			continue
		}
		prefix, vendor := rec[0], rec[1]
		switch len(prefix) {
		case 6:
			oui24[prefix] = vendor
		case 7:
			oui28[prefix] = vendor
		case 9:
			oui36[prefix] = vendor
		}
	}
}

// serviceLabel returns the embedded port service name, falling back to portCatalog
// and then "unknown".
func serviceLabel(port int) string {
	if e, ok := portsByNumber[port]; ok && e.service != "" {
		return e.service
	}
	if info, ok := portCatalog[port]; ok {
		return info.service
	}
	return "unknown"
}

// portVendors returns common software/products for a known port, or "".
func portVendors(port int) string {
	if e, ok := portsByNumber[port]; ok {
		return e.vendors
	}
	return ""
}

// macVendor returns the vendor for a MAC address using embedded OUI data, or "".
func macVendor(mac string) string {
	hex := macHexDigits(mac)
	if len(hex) < 6 {
		return ""
	}
	macVendorsOnce.Do(initMACVendors)
	for _, plen := range []int{9, 7, 6} {
		if len(hex) < plen {
			continue
		}
		prefix := hex[:plen]
		var m map[string]string
		switch plen {
		case 9:
			m = oui36
		case 7:
			m = oui28
		case 6:
			m = oui24
		}
		if vendor, ok := m[prefix]; ok {
			return vendor
		}
	}
	return ""
}

func macHexDigits(mac string) string {
	var sb strings.Builder
	sb.Grow(12)
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9':
			sb.WriteRune(r)
		case r >= 'A' && r <= 'F':
			sb.WriteRune(r)
		case r >= 'a' && r <= 'f':
			sb.WriteRune(r - 32)
		}
	}
	return sb.String()
}
