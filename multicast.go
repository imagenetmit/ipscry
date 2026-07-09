package main

import (
	"context"
	"errors"
	"net"
	"time"
)

func listenMulticastUDP(iface *net.Interface, group net.IP, port int) (*net.UDPConn, error) {
	if iface == nil {
		return nil, errors.New("missing interface")
	}
	addr := &net.UDPAddr{IP: group.To4(), Port: port}
	return net.ListenMulticastUDP("udp4", iface, addr)
}

func sendMulticastUDP(iface *net.Interface, group net.IP, port int, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	_ = iface
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: group.To4(), Port: port}
	_, err = conn.WriteTo(payload, dst)
	return err
}

func readPacketsUntil(ctx context.Context, conn net.PacketConn, deadline time.Time, handler func(net.Addr, []byte)) {
	if conn == nil {
		return
	}
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(minDuration(remaining, 250*time.Millisecond)))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		handler(addr, append([]byte(nil), buf[:n]...))
	}
}

func ifaceForTarget(targetCIDR string) (*net.Interface, net.IP, *net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(targetCIDR)
	if err != nil {
		return nil, nil, nil, err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ok := ipv4FromAddr(addr)
			if !ok || !isPrivateIPv4(ip) {
				continue
			}
			ip = ip.To4()
			if !ipNet.Contains(ip) {
				continue
			}
			return &iface, ip, ipNet, nil
		}
	}
	return nil, nil, nil, errors.New("no local interface on target subnet")
}

func discoveryEligible(targetCIDR string) (*net.Interface, net.IP, *net.IPNet, bool) {
	iface, localIP, ipNet, err := ifaceForTarget(targetCIDR)
	if err != nil {
		return nil, nil, nil, false
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 24 || !ipNet.Contains(localIP) {
		return nil, nil, nil, false
	}
	return iface, localIP, ipNet, true
}
