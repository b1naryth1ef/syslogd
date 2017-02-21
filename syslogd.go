// vim: noexpandtab tabstop=2 shiftwidth=2:
package syslogd

import (
	"net"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/rfc3164"
	"github.com/jeromer/syslogparser/rfc5424"
)

type Format int

const (
	RFC3164 Format = iota // RFC3164: http://www.ietf.org/rfc/rfc3164.txt
	RFC5424               // RFC5424: http://www.ietf.org/rfc/rfc5424.txt
)

type udpReadFunc func([]byte) (int, net.Addr, error)

type Server struct {
	Format  Format
	channel chan syslogparser.LogParts
}

// NewServer build a new server
func NewServer() *Server {
	return &Server{
		Format: RFC3164,
	}
}

func (s *Server) AddUDPListener(li net.Conn) {
	switch c := li.(type) {
	case *net.UDPConn:
		go s.handleUDP(func(buf []byte) (int, net.Addr, error) {
			return c.ReadFromUDP(buf)
		})
	case *net.UnixConn:
		go s.handleUDP(func(buf []byte) (int, net.Addr, error) {
			return c.ReadFromUnix(buf)
		})
	}
}

func (s *Server) AddTCPListener(li net.TCPListener) {
	go s.handleTCP(li)
}

func (s *Server) handleTCP(conn net.TCPListener) {
	handleTCPConn := func(client net.Conn) {
		var err error
		var sz int
		addr := client.RemoteAddr().String()
		buf := make([]byte, 4096)

		for {
			sz, err = client.Read(buf)

			if sz == 0 || err != nil {
				break
			}

			parts, err := s.parse(buf[:sz])

			if err == nil {
				parts["source"] = addr
				s.channel <- parts
			}
		}
	}

	for {
		conn, err := conn.Accept()
		if err != nil {
			panic(err)
		}

		go handleTCPConn(conn)
	}
}

func (s *Server) handleUDP(read udpReadFunc) {
	buf := make([]byte, 4096)

	for {
		n, addr, err := read(buf)

		if err != nil {
			break
		}

		parts, err := s.parse(buf[:n])

		if err == nil {
			parts["source"] = addr.String()
			s.channel <- parts
		}
	}

}

func (s *Server) parse(buf []byte) (syslogparser.LogParts, error) {

	var p syslogparser.LogParser

	switch s.Format {
	case RFC3164:
		p = rfc3164.NewParser(buf)
	case RFC5424:
		p = rfc5424.NewParser(buf)
	default:
		p = rfc3164.NewParser(buf)
	}

	err := p.Parse()

	if err != nil {
		return nil, err
	}

	parts := p.Dump()

	return parts, nil
}
