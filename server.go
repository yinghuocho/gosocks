package gosocks

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	DefaultPort = 1080
)

type SocksRequestIntercepter func(*SocksRequest, *SocksConn) bool

type Handler interface {
	ServeSocks(conn *SocksConn)
	AddSocksRequestIntercepter(SocksRequestIntercepter)
}

type ServerAuthenticator interface {
	ServerAuthenticate(conn *SocksConn) error
}

type Server struct {
	Addr    string
	Timeout time.Duration
	Handler Handler
	Auth    ServerAuthenticator
}

type UdpPacket struct {
	Addr *net.UDPAddr
	Data []byte
}

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) Serve(ln net.Listener) error {
	defer ln.Close()

	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, e := ln.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			} else {
				return e
			}
		}
		tempDelay = 0
		socks := &SocksConn{conn.(*net.TCPConn), srv.Timeout}
		if srv.Auth.ServerAuthenticate(socks) != nil {
			socks.Close()
			continue
		}
		go srv.Handler.ServeSocks(socks)
	}
}

type AnonymousServerAuthenticator struct{}

func (a *AnonymousServerAuthenticator) ServerAuthenticate(conn *SocksConn) (err error) {
	conn.SetDeadline(time.Now().Add(conn.Timeout))

	var h [smallBufSize]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, h[:2])
	if err != nil {
		return
	}

	if h[0] != SocksVersion {
		err = fmt.Errorf("Unsupported version 0x%02x", h[0])
		return
	}

	n := int(h[1])
	_, err = io.ReadFull(r, h[2:(2+n)])
	if err != nil {
		return
	}

	var buf [2]byte
	buf[0] = SocksVersion
	for i := 0; i < n; i++ {
		if h[i+3] == SocksNoAuthentication {
			buf[1] = SocksNoAuthentication
			_, err = conn.Write(buf[:])
			return
		}
	}
	buf[1] = SocksNoAcceptableMethods
	conn.Write(buf[:])
	return fmt.Errorf("NoAuthentication(0x%02x) not found in claimed methods", SocksNoAuthentication)
}

type BasicSocksHandler struct {
	intercepters []SocksRequestIntercepter
}

func (h *BasicSocksHandler) AddSocksRequestIntercepter(l SocksRequestIntercepter) {
	h.intercepters = append(h.intercepters, l)
}

func (h *BasicSocksHandler) handleCmdConnect(req *SocksRequest, conn *SocksConn) {
	addr := SockAddrString(req.DstHost, req.DstPort)
	remote, err := net.DialTimeout("tcp", addr, conn.Timeout)
	if err != nil {
		log.Printf("error in connecting remote target: %s", err)
		WriteSocksReply(conn, &SocksReply{SocksGeneralFailure, SocksIPv4Host, "0.0.0.0", 0})
		conn.Close()
		return
	}

	localAddr := remote.LocalAddr()
	hostType, host, port := NetAddrToSocksAddr(localAddr)
	_, err = WriteSocksReply(conn, &SocksReply{SocksSucceeded, hostType, host, port})
	if err != nil {
		log.Printf("error in sending reply: %s", err)
		conn.Close()
		return
	}

	CopyLoopTimeout(conn, remote, conn.Timeout)
	log.Printf("TCP connection done")
}

func (h *BasicSocksHandler) handleCmdUDPAssociate(req *SocksRequest, conn *SocksConn) {
	socksAddr := conn.LocalAddr().(*net.TCPAddr)
	clientBind, err := net.ListenUDP("udp", &net.UDPAddr{socksAddr.IP, 0, socksAddr.Zone})
	if err != nil {
		log.Printf("error in binding local UDP: %s", err)
		WriteSocksReply(conn, &SocksReply{SocksGeneralFailure, SocksIPv4Host, "0.0.0.0", 0})
		conn.Close()
		return
	}

	bindAddr := clientBind.LocalAddr()
	hostType, host, port := NetAddrToSocksAddr(bindAddr)
	log.Printf("UDP bind local address: %s", bindAddr.String())
	_, err = WriteSocksReply(conn, &SocksReply{SocksSucceeded, hostType, host, port})
	if err != nil {
		log.Printf("error in sending reply: %s", err)
		conn.Close()
		return
	}
	var clientAssociate *net.UDPAddr = SocksAddrToNetAddr("udp", req.DstHost, req.DstPort).(*net.UDPAddr)
	CopyLoopUDP(conn, clientAssociate, clientBind)
	log.Printf("UDP connection done")
}

func UdpReader(u *net.UDPConn, ch chan<- *UdpPacket) {
	u.SetDeadline(time.Time{})
	for {
		var buf [largeBufSize]byte
		n, addr, err := u.ReadFromUDP(buf[:])
		if err != nil {
			break
		}
		b := make([]byte, n)
		copy(b, buf[:n])
		ch <- &UdpPacket{addr, b}
	}
	close(ch)
}

func ConnMonitor(c net.Conn, ch chan bool) {
	c.SetDeadline(time.Time{})

	var buf [1]byte
	r := bufio.NewReader(c)
	r.Read(buf[:])
	close(ch)
}

func CopyLoopUDP(client *SocksConn, clientAssociate *net.UDPAddr, clientUDP *net.UDPConn) {
	// monitoring socks connection, quit for any reading event
	quit := make(chan bool)
	go ConnMonitor(client, quit)

	chClientUDP := make(chan *UdpPacket)
	chRemoteUDP := make(chan *UdpPacket)

	// read UPD packets
	go UdpReader(clientUDP, chClientUDP)

	// clientAddress initially set to clientAssociate
	var clientAddr *net.UDPAddr = clientAssociate
	var remoteUDP *net.UDPConn = nil
loop:
	for {
		var pkt *UdpPacket
		var ok bool
		t := time.NewTimer(client.Timeout)

		select {
		// packets from client
		case pkt, ok = <-chClientUDP:
			if !ok {
				break loop
			}
			// validation
			// 1) RFC1928 Section-7
			if !LegalClientAddr(clientAssociate, pkt.Addr) {
				continue
			}
			// 2) format
			udpReq, err := ParseUDPRequest(pkt.Data)
			if err != nil {
				log.Printf("error to parse UDP packet: %s", err)
				break loop
			}
			// 3) no fragment
			if udpReq.Frag != SocksNoFragment {
				continue
			}

			// update clientAddr (not required)
			clientAddr = pkt.Addr
			remoteAddr := SocksAddrToNetAddr("udp", udpReq.DstHost, udpReq.DstPort).(*net.UDPAddr)
			if remoteUDP == nil {
				// first packet, try to create a remoteBind to relay packet to remote
				//     1) use Dial to get correct peering IP;
				//     2) create unconnected UDP socket in order to use WriteToUDP.
				c, err := net.DialUDP("udp", nil, remoteAddr)
				if err != nil {
					log.Printf("error to connect UDP target (%s):%s", remoteAddr.String(), err)
					break loop
				}
				uaddr := c.LocalAddr().(*net.UDPAddr)
				uaddr.Port = 0
				c.Close()
				remoteUDP, _ = net.ListenUDP("udp", uaddr)
				go UdpReader(remoteUDP, chRemoteUDP)
			}
			// relay payload to remoteAddr using remoteBind
			_, err = remoteUDP.WriteToUDP(udpReq.Data, remoteAddr)
			if err != nil {
				log.Printf("error to send UDP packet to remote: %s", err)
				break loop
			}

		// packets from remote
		case pkt, ok = <-chRemoteUDP:
			if !ok {
				break loop
			}

			hostType, host, port := NetAddrToSocksAddr(pkt.Addr)
			data := PackUDPRequest(&UDPRequest{SocksNoFragment, hostType, host, port, pkt.Data})
			_, err := clientUDP.WriteToUDP(data, clientAddr)
			if err != nil {
				log.Printf("error to send UDP packet to client: %s", err)
				break loop
			}

		case <-quit:
			log.Printf("UDP unexpected event from socks connection")
			break loop

		case <-t.C:
			log.Printf("UDP timeout")
			break loop
		}
		t.Stop()
	}

	client.Close()
	clientUDP.Close()
	if remoteUDP != nil {
		remoteUDP.Close()
	} else {
		close(chRemoteUDP)
	}
	// readeres may block on writing, try read to wake them so they
	// are aware that the underlying connection has closed.
	<-chClientUDP
	<-chRemoteUDP
}

func CopyLoopTimeout(c1 net.Conn, c2 net.Conn, timeout time.Duration) {
	ch1 := make(chan []byte)
	ch2 := make(chan []byte)

	reader := func(c net.Conn, ch chan<- []byte) {
		c.SetDeadline(time.Time{})

		var buf [largeBufSize]byte
		r := bufio.NewReader(c)
		for {
			n, err := r.Read(buf[:])
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				ch <- b
			}
			if err != nil {
				break
			}
		}
		close(ch)
	}

	go reader(c1, ch1)
	go reader(c2, ch2)

loop:
	for {
		t := time.NewTimer(timeout)
		var buf []byte
		var ok bool
		select {
		case buf, ok = <-ch1:
			if !ok {
				break loop
			}
			_, err := c2.Write(buf)
			if err != nil {
				break loop
			}

		case buf, ok = <-ch2:
			if !ok {
				break loop
			}
			_, err := c1.Write(buf)
			if err != nil {
				break loop
			}

		case <-t.C:
			log.Printf("CopyLoop timeout")
			break loop
		}
		t.Stop()
	}

	c1.Close()
	c2.Close()
	// readeres may block on writing, try read to wake them so they
	// are aware that the underlying connection has closed.
	<-ch1
	<-ch2
}

func (h *BasicSocksHandler) ServeSocks(conn *SocksConn) {
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	req, err := ReadSocksRequest(conn)
	if err != nil {
		log.Printf("error in ReadSocksRequest: %s", err)
		return
	}

	for _, f := range h.intercepters {
		if f(&req, conn) {
			return
		}
	}

	switch req.Cmd {
	case SocksCmdConnect:
		h.handleCmdConnect(&req, conn)
	case SocksCmdUDPAssociate:
		h.handleCmdUDPAssociate(&req, conn)
	case SocksCmdBind:
		conn.Close()
		return
	default:
		return
	}
}

func NewServer(addr string, to time.Duration) *Server {
	return &Server{
		Addr:    addr,
		Timeout: to,
		Handler: &BasicSocksHandler{},
		Auth:    &AnonymousServerAuthenticator{},
	}
}
