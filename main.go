package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

var (
	myDomain = flag.String("domain", "ip.yamagishi.net", "Domain name to accept requests")
	bindIp = flag.String("bind", "0.0.0.0", "Address to listen")
	bindPort = flag.Int("port", 53, "Port number to listen")
)

type afi_t int
const (
	afi_ipv4 = iota
	afi_ipv6
	afi_max
)

func getClientIp(writer dns.ResponseWriter) (net.IP, afi_t) {
	var ipAddr net.IP

	// :(
	ipUdpAddr, ok := writer.RemoteAddr().(*net.UDPAddr)
	if ok {
		ipAddr = ipUdpAddr.IP
	} else {
		ipTcpAddr, ok := writer.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil, afi_max
		}
		ipAddr = ipTcpAddr.IP
	}

	if ipAddr.To4() != nil {
		return ipAddr, afi_ipv4
	} else {
		return ipAddr, afi_ipv6
	}

	// should not reach here
	return nil, afi_max
}

func respondClientIp(writer dns.ResponseWriter, req *dns.Msg) {
	clientIp, afi := getClientIp(writer)
	replyMsg := new(dns.Msg)
	replyMsg.SetReply(req)
	switch(afi) {
		case afi_ipv4:
			rr := &dns.A {
				Hdr: dns.RR_Header {
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A:   clientIp.To4(),
			}
			replyMsg.Answer = append(replyMsg.Answer, rr)
			break

		case afi_ipv6:
			rr := &dns.AAAA {
				Hdr: dns.RR_Header {
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				AAAA:   clientIp,
			}
			replyMsg.Answer = append(replyMsg.Answer, rr)
			break

		default:
			// Client IP Parser Errors will be caught here
			fmt.Errorf("Error: afi = %d", afi)
			replyMsg.SetRcode(req, dns.RcodeNameError)
	}
	writer.WriteMsg(replyMsg)
	return
}

func respondIpv4InRequest(writer dns.ResponseWriter, req *dns.Msg) {
	// parse ip from request
	hostname := strings.Split(req.Question[0].Name, ".") // get a-b-c-d from a-b-c-d.domain.com.
	ipSplitStr := strings.Split(hostname[0], "-") // get a, b, c, d from a-b-c-d
	ipStr := fmt.Sprintf("%s.%s.%s.%s", ipSplitStr[0], ipSplitStr[1],
					    ipSplitStr[2], ipSplitStr[3])
	ipAddr := net.ParseIP(ipStr)
	if ipAddr.To4() == nil {
		fmt.Printf("Request is invalid: %s\n", req.Question[0].Name)
		return
	}

	replyMsg := new(dns.Msg)
	replyMsg.SetReply(req)
	rr := &dns.A {
		Hdr: dns.RR_Header {
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A:   ipAddr.To4(),
	}
	replyMsg.Answer = append(replyMsg.Answer, rr)
	writer.WriteMsg(replyMsg)

	return
}

func requestHandler(writer dns.ResponseWriter, req *dns.Msg) {
	fmt.Printf("Got request %s (%d)\n", req.Question[0].Name, req.Question[0].Qtype)

	switch req.Question[0].Qtype {
		case dns.TypeA:
		case dns.TypeAAAA:
			break

		default:
			fmt.Printf("Ignoring request as Qtype is unsupported")
			return
	}

	clientIpResponder := fmt.Sprintf("my.%s.", *myDomain)
	switch req.Question[0].Name {
		case clientIpResponder:
			respondClientIp(writer, req)
			break
		default:
			// TODO: IPv6 Support..
			respondIpv4InRequest(writer, req)
			break
	}

	return
}

func handlerLoop(bindAddr string, proto string) {
	server := &dns.Server{
		Addr: bindAddr,
		Net:  proto,
	}

	fmt.Printf("Starting server at %s (%s)\n", bindAddr, proto)

	err := server.ListenAndServe()
	if err != nil {
		fmt.Errorf("Failed to start server: %s\n", err)
	}

	return
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	if *bindPort < 1 || *bindPort > 65535 {
		fmt.Printf("Port number is out of range: %d", *bindPort)
		return
	}

	bindAddr := fmt.Sprintf("%s:%d", *bindIp, *bindPort)
	dns.HandleFunc(*myDomain, requestHandler)
	go handlerLoop(bindAddr, "tcp")
	go handlerLoop(bindAddr, "udp")

	// wait
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigChan

	fmt.Printf("%s: stopping server..\n", sig)
}
