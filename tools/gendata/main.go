//go:build ignore

// gendata converts mac-vendors-export.json into data/mac_vendors.csv.gz for
// embedding. Run via: go generate ./...
package main

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type macEntry struct {
	MACPrefix  string `json:"macPrefix"`
	VendorName string `json:"vendorName"`
	Private    bool   `json:"private"`
}

func main() {
	inPath := "mac-vendors-export.json"
	outPath := "data/mac_vendors.csv.gz"
	if len(os.Args) >= 2 {
		inPath = os.Args[1]
	}
	if len(os.Args) >= 3 {
		outPath = os.Args[2]
	}

	raw, err := os.ReadFile(inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	var entries []macEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	type row struct {
		prefix string
		vendor string
	}
	var rows []row
	for _, e := range entries {
		if e.Private || strings.TrimSpace(e.VendorName) == "" {
			continue
		}
		prefix := prefixHex(e.MACPrefix)
		switch len(prefix) {
		case 6, 7, 9:
		default:
			continue
		}
		rows = append(rows, row{prefix: prefix, vendor: e.VendorName})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].prefix < rows[j].prefix })

	if err := os.MkdirAll("data", 0755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	w := csv.NewWriter(gz)
	for _, r := range rows {
		if err := w.Write([]string{r.prefix, r.vendor}); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "flush:", err)
		os.Exit(1)
	}
	if err := gz.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "gzip close:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d entries to %s\n", len(rows), outPath)
}

func prefixHex(macPrefix string) string {
	var sb strings.Builder
	for _, r := range macPrefix {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			sb.WriteRune(r)
		case r >= 'a' && r <= 'f':
			sb.WriteRune(r - 32)
		}
	}
	return sb.String()
}
