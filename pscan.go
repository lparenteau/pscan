/*
    pscan : port scanner
    Copyright (C) 2016  Laurent Parenteau

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import "fmt"
import "os"
import "net"
import "time"
import "encoding/binary"
import "bytes"
import "golang.org/x/net/icmp"
import "bufio"
import "strings"
import "strconv"

// values copied from 'internal/iana'
const (
    ProtocolICMP           = 1   // Internet Control Message
    ProtocolIPv6ICMP       = 58  // ICMP for IPv6
)

// semaphores, see http://www.golangpatterns.info/concurrency/semaphores
type empty struct{}
type semaphore chan empty

func (s semaphore) P(n int) {
    e := empty{}
    for i := 0; i < n; i++ {
        s <- e
    }
}

func (s semaphore) V(n int) {
    for i := 0; i < n; i++ {
        <-s
    }
}

func (s semaphore) Signal() {
    s.V(1)
}

func (s semaphore) Wait(n int) {
    s.P(n)
}

// reverse service lookup, inspired from https://golang.org/src/net/port_unix.go
var services = make(map[string]map[int]string)

func readServices() {
    var file *os.File
    var err error
    if file, err = os.Open("/etc/services"); err != nil {
        return
    }

    var line string
    r := bufio.NewReader(file)
    for line, err = r.ReadString('\n'); err == nil; line, err = r.ReadString('\n') {
        // "http 80/tcp www www-http # World Wide Web HTTP"
        if i := strings.IndexByte(line, '#'); i >= 0 {
            line = line[0:i]
        }
        f := strings.Fields(line)
        if len(f) < 2 {
            continue
        }
        portnet := f[1] // "80/tcp"
        j := strings.Index(portnet, "/")
        if j >= len(portnet) || portnet[j] != '/' {
            continue
        }
        port, err := strconv.Atoi(portnet[0:j])
        if err != nil || port <= 0 {
            continue
        }
        netw := portnet[j+1:] // "tcp"
        m, ok := services[netw]
        if !ok {
            m = make(map[int]string)
            services[netw] = m
        }
        for i := 0; i < len(f); i++ {
            if i != 1 { // f[1] was port/net
                m[port] = f[i]
            }
        }
    }
    
    file.Close()
}

func reverseLookupPort(network string, port int) (string) {
    if m, ok := services[network]; ok {
        if service, ok1 := m[port]; ok1 {
            return service
        }
    }
    
    return "unknown"
}

// scan (TCP + UDP) a single IP (IPv4 or IPv6) address
func scanIP(ip net.IP) ([]bool, []bool) {
    timeout := time.Second * 5
    results_tcp := make([]bool, 65535)
    var results_udp []bool = nil
    sem := make(semaphore, len(results_tcp))

    ipStr := fmt.Sprint(ip)
    if ip.To4() == nil {
        ipStr = fmt.Sprint("[", ip, "]")
    }

    fmt.Printf("Scanning IP : %v\n", ip)

    // start with TCP ports, all at the same time, using goroutines
    fmt.Printf("  checking TCP.\n")
    for port := 1; port <= len(results_tcp); port++ {
        go func (port int) {
            conn, err := net.DialTimeout("tcp", fmt.Sprint(ipStr, ":", port), timeout)
            if err != nil {
                results_tcp[port-1] = false
            }
            if conn != nil {
                conn.Close()
                results_tcp[port-1] = true
            }
            sem.Signal()
        } (port)
    }

    // For UDP scan, we need to be able to receives ICMP packets.  To do so, we must know the local IP address
    // that will be used when we send the UDP packets to the ip we are scanning
    var icmpListener net.PacketConn = nil
    skip_udp := false
    proto := 0
    conn, err := net.DialTimeout("udp", fmt.Sprint(ipStr, ":", 123), timeout)
    if err != nil {
        // Unable to open socket for local ip lookup, skip UDP scanning
        skip_udp = true
    } else {
        local := conn.LocalAddr()
        local_host, _, err := net.SplitHostPort(local.String())
        if err != nil {
            // Unable to parse local ip, skip UDP scanning
            skip_udp = true
        } else {
            if (net.ParseIP(local_host).To4() == nil) {
                icmpListener, err = icmp.ListenPacket("ip6:ipv6-icmp", local_host)
                proto = ProtocolIPv6ICMP
            } else {
                icmpListener, err = icmp.ListenPacket("ip4:icmp", local_host)
                proto = ProtocolICMP
            }
            if err != nil {
                // Unable to setup ICMP listener (we are probably not root), skip UDP scanning
                skip_udp = true
            }
        }
        conn.Close()
    }
    if skip_udp {
        fmt.Printf("  can't listen to ICMP, skipping UDP scanning.\n")
    } else {
        results_udp = make([]bool, len(results_tcp))
        // Start the ICMP listening process in background, since those won't necessarly match the sending order
        // and can take some time to come back.
        go func () {
            for {
                buffer := make([]byte, 128)
                length, sourceIP, err := icmpListener.ReadFrom(buffer[0:])
                if err != nil {
                    continue
                }
                if ip.Equal(net.ParseIP(sourceIP.String())) {
                    msg, err := icmp.ParseMessage(proto, buffer[:length])
                    if (err == nil) && (proto == ProtocolICMP && msg.Code == 3) || (proto == ProtocolIPv6ICMP && msg.Code == 4) {
                        buffer, err = msg.Body.Marshal(proto)
                        if (err == nil) {
                            var port uint16
                            offset := 26
                            if proto == ProtocolIPv6ICMP {
                                offset = 46
                            }
                            buf := bytes.NewReader(buffer[offset:])
                            binary.Read(buf, binary.BigEndian, &port)
                            results_udp[port-1] = false
                        }
                    }
                }
            }
        } ()

        // Start scanning UDP.  We do it 1 at once in a controlled fashion, otherwise it may happen :
        //   1- UDP packet dropped by our own stack
        //   2- UDP packet dropped by any router in between
        //   3- ICMP sending threshold of target IP prevent sending the ICMP packets we needs
        // In all those case, we will have to claim the UDP port as open, but it might (likely will) not be true.
        fmt.Printf("  checking UDP (this takes time, have a coffee).\n")
        fmt.Printf("  ")
        for port := 1; port <= len(results_udp); port++ {
            // This will take some time, have some progress displayed; be nice to user.
            if port % 1000 == 0 {
                fmt.Printf(".")
            }
            results_udp[port-1] = true
            conn, err := net.DialTimeout("udp", fmt.Sprint(ipStr, ":", port), timeout)
            if err != nil {
                results_udp[port-1] = false
            }
            if conn != nil {
                len,err := conn.Write([]byte("a"))
                if err != nil || len == 0 {
                    results_udp[port-1] = false
                }
                conn.Close()
            }
            // Limit our sending rate
            time.Sleep(2 * time.Millisecond)
        }
        fmt.Printf("\n")
    }

    // Just in case TCP isn't over yet... but it will be for sure if UDP scanning is done.
    sem.Wait(len(results_tcp))

    if icmpListener != nil {
        icmpListener.Close()
    }
    
    return results_tcp, results_udp
}

func getNextIP(ip net.IP) (net.IP) {
    for i := 3; i >= 0; i-- {
        ip[i]++
        if ip[i] != 0 {
            break
        }
    }
    return ip
}

// main, let's go
func main() {
    // Load services for reverse port lookup
    readServices()
    
    // checking arguments
    if len(os.Args) != 2 {
        fmt.Printf("Missing IP address to scan\n")
        os.Exit(1)
    }
    
    // Check if it's an IPv4 network block
    ip, network, err := net.ParseCIDR(os.Args[1])
    if err != nil {
        // If not, is this a single IPv4 / IPv6 address
        ip = net.ParseIP(os.Args[1])
        if ip == nil {
            fmt.Printf("Error parsing IP address (%s) : %s\n", os.Args[1], err.Error())
            os.Exit(1)
        }
    }

    for {
        results_tcp, results_udp := scanIP(ip)

        // Report our results
        fmt.Printf("Results :\n")
        for port := 1; port <= len(results_tcp); port++ {
            if results_tcp[port-1] {
                service := reverseLookupPort("tcp", port)
                fmt.Printf("  TCP port %d (%s) is open\n", port, service)
            }
        }
        if results_udp != nil {
            for port := 1; port <= len(results_udp); port++ {
                if results_udp[port-1] {
                    service := reverseLookupPort("udp", port)
                    fmt.Printf("  UDP port %d (%s) is open\n", port, service)
                }
            }
        }
        
        // If we have an IPv4 address and a valid network block, scan the next IP address
        // if it is inside that network block
        ip = ip.To4()
        if network != nil && ip != nil {
            ip = getNextIP(ip)
            
            if network.Contains(ip) == false {
                break
            }                
        } else {
            break
        }
        fmt.Printf("\n")
    }
}
