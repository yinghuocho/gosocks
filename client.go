package gosocks

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"time"
)

func Dial(address string, timeout time.Duration) (conn *SocksConn, err error) {
	c, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	conn = &SocksConn{c.(*net.TCPConn), timeout}
	err = ClientAuthAnonymous(conn)
	if err != nil {
		conn.Close()
		return
	}
	return
}

func ClientAuthAnonymous(conn *SocksConn) (err error) {
	conn.SetDeadline(time.Now().Add(conn.Timeout))

	var req [3]byte
	req[0] = SocksVersion
	req[1] = 1
	req[2] = SocksNoAuthentication
	_, err = conn.Write(req[:])
	if err != nil {
		return
	}

	var resp [2]byte
	r := bufio.NewReader(conn)
	_, err = io.ReadFull(r, resp[:2])
	if err != nil {
		return
	}
	if resp[0] != SocksVersion || resp[1] != SocksNoAuthentication {
		err = fmt.Errorf("Fail to pass anonymous authentication: (0x%02x, 0x%02x)", resp[0], resp[1])
		return
	}
	return
}

func ClientRequest(conn *SocksConn, req *SocksRequest) (reply SocksReply, err error) {
	_, err = WriteSocksRequest(conn, req)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(conn.Timeout))
	reply, err = ReadSocksReply(conn)
	return
}
