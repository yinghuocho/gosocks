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

type Handler interface {
	ServeSocks(conn *SocksConn)
}

type ServerAuthenticator interface {
	ServerAuthenticate(conn *SocksConn) error
}

type Server struct {
	addr    string
	timeout time.Duration
	handler Handler
	auth    ServerAuthenticator
	msgCh   chan interface{}
	quit    chan bool
}

type UDPPacket struct {
	Addr *net.UDPAddr
	Data []byte
}

func (svr *Server) ListenAndServe() error {
	addr := svr.addr
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return svr.Serve(ln)
}

func (svr *Server) GetTimeout() time.Duration {
	return svr.timeout
}

// safely change authenticator when server is running
func (svr *Server) ChangeAuth(auth ServerAuthenticator) {
	select {
	case svr.msgCh <- auth:
	case <-svr.quit:
	}
}

func (svr *Server) ChangeHandler(handler Handler) {
	select {
	case svr.msgCh <- handler:
	case <-svr.quit:
	}
}

type ret struct {
	conn net.Conn
	err  error
}

func (svr *Server) Serve(ln net.Listener) error {
	// close quit channel after loop ends, so that attempts to change
	// authenticator or handler do not block.
	defer close(svr.quit)

	ch := make(chan ret)
	go func() {
		// how long to sleep on accept failure
		var tempDelay time.Duration
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
					ch <- ret{nil, e}
					return
				}
			}
			tempDelay = 0
			ch <- ret{conn, e}
		}
	}()

	for {
		select {
		case r := <-ch:
			if r.err != nil {
				return r.err
			}

			go func(c net.Conn, to time.Duration, auth ServerAuthenticator, handler Handler) {
				socks := &SocksConn{c, to}
				// if svr.Auth is nil, Handler should process authenticate.
				if auth != nil {
					if auth.ServerAuthenticate(socks) != nil {
						socks.Close()
						return
					}
				}
				handler.ServeSocks(socks)
			}(r.conn, svr.timeout, svr.auth, svr.handler)
		case msg := <-svr.msgCh:
			switch msg.(type) {
			case ServerAuthenticator:
				svr.auth = msg.(ServerAuthenticator)
			case Handler:
				svr.handler = msg.(Handler)
			}
		}
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

type BasicSocksHandler struct{}

func (h *BasicSocksHandler) HandleCmdConnect(req *SocksRequest, conn *SocksConn) {
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

func (h *BasicSocksHandler) HandleCmdUDPAssociate(req *SocksRequest, conn *SocksConn) {
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

func UDPReader(u *net.UDPConn, ch chan<- *UDPPacket) {
	u.SetDeadline(time.Time{})
	var buf [largeBufSize]byte
	for {
		n, addr, err := u.ReadFromUDP(buf[:])
		if err != nil {
			break
		}
		b := make([]byte, n)
		copy(b, buf[:n])
		ch <- &UDPPacket{addr, b}
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

	chClientUDP := make(chan *UDPPacket)
	chRemoteUDP := make(chan *UDPPacket)

	// read UPD packets
	go UDPReader(clientUDP, chClientUDP)

	// clientAddress initially set to clientAssociate
	var clientAddr *net.UDPAddr = clientAssociate
	var remoteUDP *net.UDPConn = nil
loop:
	for {
		var pkt *UDPPacket
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
				go UDPReader(remoteUDP, chRemoteUDP)
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
	ch1 := make(chan bool, 5)
	ch2 := make(chan bool, 5)
	copyer := func(src net.Conn, dst net.Conn, ch chan<- bool) {
		var buf [largeBufSize]byte
		for {
			nr, er := src.Read(buf[:])
			if nr > 0 {
				nw, ew := dst.Write(buf[0:nr])
				if ew != nil {
					break
				}
				if nr != nw {
					break
				}
				ch <- true
			}
			if er != nil {
				break
			}
		}
		close(ch)
	}

	go copyer(c1, c2, ch1)
	go copyer(c2, c1, ch2)

loop:
	for {
		t := time.NewTimer(timeout)
		var ok bool
		select {
		case _, ok = <-ch1:
			if !ok {
				break loop
			}

		case _, ok = <-ch2:
			if !ok {
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
}

func (h *BasicSocksHandler) ServeSocks(conn *SocksConn) {
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	req, err := ReadSocksRequest(conn)
	if err != nil {
		log.Printf("error in ReadSocksRequest: %s", err)
		return
	}

	switch req.Cmd {
	case SocksCmdConnect:
		h.HandleCmdConnect(&req, conn)
		return
	case SocksCmdUDPAssociate:
		h.HandleCmdUDPAssociate(&req, conn)
		return
	case SocksCmdBind:
		conn.Close()
		return
	default:
		return
	}
}

func NewBasicServer(addr string, to time.Duration) *Server {
	return &Server{
		addr:    addr,
		timeout: to,
		handler: &BasicSocksHandler{},
		auth:    &AnonymousServerAuthenticator{},
		msgCh:   make(chan interface{}),
		quit:    make(chan bool),
	}
}

func NewServer(addr string, to time.Duration, handler Handler, auth ServerAuthenticator) *Server {
	return &Server{
		addr:    addr,
		timeout: to,
		handler: handler,
		auth:    auth,
		msgCh:   make(chan interface{}),
		quit:    make(chan bool),
	}
}
