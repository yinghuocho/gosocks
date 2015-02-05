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

type Server struct {
	Addr    string
	Timeout time.Duration
	Handler Handler
	Logger  SocksLogger
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
		go srv.Handler.ServeSocks(&SocksConn{conn.(*net.TCPConn), srv.Timeout, srv.Logger})
	}
}

type basicSocksHandler struct{}

func (h *basicSocksHandler) handleCmdConnect(req *SocksRequest, conn *SocksConn) {
	addr := SockAddrString(req.DstHost, req.DstPort)
	remote, err := net.DialTimeout("tcp", addr, conn.Timeout)
	if err != nil {
		log.Printf("error in connecting remote target: %s", err)
		WriteSocksReply(conn, &SocksReply{SocksGeneralFailure, SocksIPv4Host, "0.0.0.0", 0})
		return
	}

	localAddr := remote.LocalAddr()
	hostType, host, port := NetAddrToSocksAddr(localAddr)
	_, err = WriteSocksReply(conn, &SocksReply{SocksSucceeded, hostType, host, port})
	if err != nil {
		log.Printf("error in sending reply: %s", err)
		return
	}

	copyLoopTCP(conn, remote.(*net.TCPConn))
	log.Printf("TCP connection done")
}

func (h *basicSocksHandler) handleCmdUDPAssociate(req *SocksRequest, conn *SocksConn) {
	socksAddr := conn.LocalAddr().(*net.TCPAddr)
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{socksAddr.IP, 0, socksAddr.Zone})
	if err != nil {
		log.Printf("error in binding local UDP: %s", err)
		WriteSocksReply(conn, &SocksReply{SocksGeneralFailure, SocksIPv4Host, "0.0.0.0", 0})
		return
	}

	bindAddr := clientConn.LocalAddr()
	hostType, host, port := NetAddrToSocksAddr(bindAddr)
	log.Printf("UDP bind local address: %s", bindAddr.String())
	_, err = WriteSocksReply(conn, &SocksReply{SocksSucceeded, hostType, host, port})
	if err != nil {
		log.Printf("error in sending reply: %s", err)
		return
	}
	var clientAssociate *net.UDPAddr = SocksAddrToNetAddr("udp", req.DstHost, req.DstPort).(*net.UDPAddr)
	copyLoopUDP(clientAssociate, conn, clientConn)
	log.Printf("UDP connection done")
}

func copyLoopUDP(clientAssociate *net.UDPAddr, conn *SocksConn, clientConn *net.UDPConn) {
	// monitoring socks connection, quit for any reading event
	quit := make(chan bool)
	go func() {
		// set KeepAlive to detect dead connection
		conn.SetDeadline(time.Time{})
		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(conn.Timeout)

		var buf [1]byte
		r := bufio.NewReader(conn)
		r.Read(buf[:])
		close(quit)
	}()

	chClient := make(chan udpPacket)
	chRemote := make(chan udpPacket)

	// read UPD packets
	readFunc := func(u *net.UDPConn, ch chan<- udpPacket) {
		u.SetDeadline(time.Time{})

		for {
			var buf [largeBufSize]byte
			n, addr, err := u.ReadFromUDP(buf[:])
			if err != nil {
				break
			}
			// log.Printf("UDP from %s : len %d", addr.String(), n)
			b := make([]byte, n)
			copy(b, buf[:n])
			ch <- udpPacket{addr, b}
		}
		close(ch)
	}

	go readFunc(clientConn, chClient)

	var clientAddr *net.UDPAddr = clientAssociate
	var remoteConn *net.UDPConn = nil
loop:
	for {
		var pkt udpPacket
		var ok bool

		select {
		case pkt, ok = <-chClient:
			if !ok {
				break loop
			}

			// RFC1928 Section-7
			if !LegalClientAddr(clientAssociate, pkt.addr) {
				continue
			}
			udpReq, err := ParseUDPRequest(pkt.data)
			if err != nil {
				log.Printf("error to parse UDP packet: %s", err)
				break loop
			}
			if udpReq.Frag != SocksNoFragment {
				continue
			}

			clientAddr = pkt.addr
			remoteAddr := SocksAddrToNetAddr("udp", udpReq.DstHost, udpReq.DstPort).(*net.UDPAddr)
			if remoteConn == nil {
				// use DialUDP to find a local IP, then switch to ListenUDP.
				// Because DialUDP returns a connected UDPConn which cannot use
				// WriteToUDP.
				remoteConn, err = net.DialUDP("udp", nil, remoteAddr)
				if err != nil {
					log.Printf("error to connect UDP target (%s):%s", remoteAddr.String(), err)
					break loop
				}
				uaddr := remoteConn.LocalAddr().(*net.UDPAddr)
				uaddr.Port = 0
				remoteConn.Close()
				remoteConn, _ = net.ListenUDP("udp", uaddr)
				go readFunc(remoteConn, chRemote)
			}

			_, err = remoteConn.WriteToUDP(udpReq.Data, remoteAddr)
			if err != nil {
				log.Printf("error to send UDP packet to remote: %s", err)
				break loop
			}

		case pkt, ok = <-chRemote:
			if !ok {
				break loop
			}

			hostType, host, port := NetAddrToSocksAddr(pkt.addr)
			data := PackUDPRequest(&UDPRequest{SocksNoFragment, hostType, host, port, pkt.data})
			_, err := clientConn.WriteToUDP(data, clientAddr)
			if err != nil {
				log.Printf("error to send UDP packet to client: %s", err)
				break loop
			}

		case <-quit:
			log.Printf("UDP unexpected event from socks connection")
			break loop

		case <-time.After(conn.Timeout):
			log.Printf("UDP timeout")
			break loop
		}
	}

	conn.Close()
	clientConn.Close()
	if remoteConn != nil {
		remoteConn.Close()
	} else {
		close(chRemote)
	}

	// make sure spawned goroutines quit ?
	<-chClient
	<-chRemote
}

func copyLoopTCP(conn *SocksConn, remote *net.TCPConn) {
	chClient := make(chan []byte)
	chRemote := make(chan []byte)

	readFunc := func(c *net.TCPConn, ch chan<- []byte) {
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

	go readFunc(conn.TCPConn, chClient)
	go readFunc(remote, chRemote)

loop:
	for {
		var buf []byte
		var ok bool
		select {
		case buf, ok = <-chClient:
			if !ok {
				break loop
			}
			_, err := remote.Write(buf)
			if err != nil {
				break loop
			}

		case buf, ok = <-chRemote:
			if !ok {
				break loop
			}
			_, err := conn.Write(buf)
			if err != nil {
				break loop
			}

		case <-time.After(conn.Timeout):
			log.Printf("TCP timeout")
			break loop
		}
	}

	conn.Close()
	remote.Close()
	// make sure spawned goroutines quit ?
	<-chRemote
	<-chClient
}

// Receive auth request, then reply
func ServerAuthAnonymous(conn *SocksConn) (err error) {
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

	for i := 0; i < n; i++ {
		if h[i+3] == SocksNoAuthentication {
			var buf [2]byte
			buf[0] = SocksVersion
			buf[1] = SocksNoAuthentication
			_, err = conn.Write(buf[:])
			return
		}
	}
	return fmt.Errorf("NoAuthentication(0x%02x) not found in claimed methods", SocksNoAuthentication)
}

func (h *basicSocksHandler) ServeSocks(conn *SocksConn) {
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	err := ServerAuthAnonymous(conn)
	if err != nil {
		log.Printf("error in AnonymousAuth: %s", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	req, err := ReadSocksRequest(conn)
	if err != nil {
		log.Printf("error in ReadSocksRequest: %s", err)
		return
	}

	conn.Logger.LogSocksRequest(&req)
	switch req.Cmd {
	case SocksCmdConnect:
		h.handleCmdConnect(&req, conn)
	case SocksCmdUDPAssociate:
		h.handleCmdUDPAssociate(&req, conn)
	case SocksCmdBind:
		return
	default:
		return
	}
}

func NewServer(addr string, to time.Duration) *Server {
	return &Server{Addr: addr, Timeout: to, Handler: &basicSocksHandler{}, Logger: &dummySocksLogger{}}
}
