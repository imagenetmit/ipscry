package main

import (
	"encoding/binary"
	"net"
	"strings"
)

const (
	dnsTypeA    = 1
	dnsTypePTR  = 12
	dnsTypeTXT  = 16
	dnsTypeAAAA = 28
	dnsTypeSRV  = 33
)

type dnsRecord struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	Data        []byte
	RDataOffset int
}

type dnsPacket struct {
	ID      uint16
	Flags   uint16
	Records []dnsRecord
}

func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func decodeDNSName(msg []byte, offset int) (string, int, error) {
	var labels []string
	visited := map[int]bool{}
	for offset < len(msg) {
		if visited[offset] {
			return "", offset, nil
		}
		visited[offset] = true
		if offset >= len(msg) {
			break
		}
		length := int(msg[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3fff)
			name, _, _ := decodeDNSName(msg, ptr)
			if name != "" {
				labels = append(labels, name)
			}
			offset += 2
			break
		}
		offset++
		end := offset + length
		if end > len(msg) {
			break
		}
		labels = append(labels, string(msg[offset:end]))
		offset = end
	}
	return strings.Join(labels, "."), offset, nil
}

func buildDNSQuery(id uint16, name string, qtype uint16, unicastResponse bool) []byte {
	flags := uint16(0)
	if unicastResponse {
		flags = 0x8000
	}
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	out = append(out, encodeDNSName(name)...)
	out = append(out, byte(qtype>>8), byte(qtype))
	out = append(out, 0x00, 0x01) // class IN
	return out
}

func parseDNSPacket(data []byte) (dnsPacket, bool) {
	if len(data) < 12 {
		return dnsPacket{}, false
	}
	pkt := dnsPacket{
		ID:    binary.BigEndian.Uint16(data[0:2]),
		Flags: binary.BigEndian.Uint16(data[2:4]),
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	ns := int(binary.BigEndian.Uint16(data[8:10]))
	ar := int(binary.BigEndian.Uint16(data[10:12]))
	offset := 12
	for i := 0; i < qd; i++ {
		_, next, err := decodeDNSName(data, offset)
		if err != nil || next+4 > len(data) {
			return dnsPacket{}, false
		}
		offset = next + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, next, err := decodeDNSName(data, offset)
		if err != nil || next+10 > len(data) {
			break
		}
		rtype := binary.BigEndian.Uint16(data[next : next+2])
		class := binary.BigEndian.Uint16(data[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(data[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
		next += 10
		if next+rdlen > len(data) {
			break
		}
		rdata := append([]byte(nil), data[next:next+rdlen]...)
		pkt.Records = append(pkt.Records, dnsRecord{
			Name:        name,
			Type:        rtype,
			Class:       class,
			TTL:         ttl,
			Data:        rdata,
			RDataOffset: next,
		})
		offset = next + rdlen
	}
	return pkt, true
}

func dnsRecordIPv4(rec dnsRecord) string {
	if rec.Type != dnsTypeA || len(rec.Data) != 4 {
		return ""
	}
	return net.IP(rec.Data).String()
}

func dnsRecordIPv6(rec dnsRecord) string {
	if rec.Type != dnsTypeAAAA || len(rec.Data) != 16 {
		return ""
	}
	return net.IP(rec.Data).String()
}

func dnsRecordName(msg []byte, rec dnsRecord) string {
	if rec.Type != dnsTypePTR && rec.Type != dnsTypeSRV {
		return ""
	}
	offset := rec.RDataOffset
	if rec.Type == dnsTypeSRV {
		offset += 6
	}
	if offset < 0 || offset >= len(msg) {
		return ""
	}
	name, _, _ := decodeDNSName(msg, offset)
	return strings.TrimSuffix(sanitizeOneLine(name), ".")
}

func dnsRecordTXT(rec dnsRecord) string {
	if rec.Type != dnsTypeTXT || len(rec.Data) == 0 {
		return ""
	}
	var parts []string
	offset := 0
	for offset < len(rec.Data) {
		length := int(rec.Data[offset])
		offset++
		if offset+length > len(rec.Data) {
			break
		}
		parts = append(parts, string(rec.Data[offset:offset+length]))
		offset += length
	}
	return sanitizeOneLine(strings.Join(parts, " "))
}
