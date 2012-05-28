package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
)

type certPool struct {
	mutex sync.Mutex
	certs map[string]*tls.Certificate
}

func newCertPool() *certPool {
	return &certPool{certs: make(map[string]*tls.Certificate)}
}

func (cp *certPool) getCert(host string) (*tls.Certificate, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cert, ok := cp.certs[host]
	if !ok {
		var err error
		cert, err = GenHostCert(CACert, CAKey, host)
		if err != nil {
			return nil, err
		}
		cp.certs[host] = cert
	}
	return cert, nil
}

type conn struct {
	rw  net.Conn
	br  *bufio.Reader
	bw  *bufio.Writer
	ps  *ProxyServer
	url string
}

func newConn(rw net.Conn, ps *ProxyServer) *conn {
	c := new(conn)
	c.rw = rw
	c.br = bufio.NewReader(c.rw)
	c.bw = bufio.NewWriter(c.rw)
	c.ps = ps
	return c
}

func (c *conn) serve() {
	defer c.rw.Close()
	for {
		req, err := http.ReadRequest(c.br)
		if err != nil {
			if err == io.EOF {
				return
			} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return
			}
			log.Printf("connection error: %s", err)
			return
		}
		if req.Method == "CONNECT" {
			host := strings.SplitN(req.URL.Host, ":", 2)[0]
			cert, err := c.ps.certPool.getCert(host)
			if err != nil {
				log.Printf("getCert error: %s", err)
				return
			}
			config := &tls.Config{Certificates: []tls.Certificate{*cert}}
			c.bw.WriteString("HTTP/1.0 200 OK\r\n\r\n")
			c.bw.Flush()
			c.rw = tls.Server(c.rw, config)
			c.br = bufio.NewReader(c.rw)
			c.bw = bufio.NewWriter(c.rw)
			c.url = "https://" + host
			continue
		}
		err = c.handle(c.bw, req)
		if err != nil {
			return
		}
	}
	panic("not reach")
}

func (c *conn) handle(w *bufio.Writer, r *http.Request) error {
	// fetch request body
	buf := &bytes.Buffer{}
	zbuf, err := zlib.NewWriterLevel(buf, zlib.BestCompression)
	if err != nil {
		return err
	}
	url := c.url + r.URL.String()
	urlhex := make([]byte, hex.EncodedLen(len(url)))
	hex.Encode(urlhex, []byte(url))
	fmt.Fprintf(zbuf, "url=%s", urlhex)
	fmt.Fprintf(zbuf, "&method=%s", hex.EncodeToString([]byte(r.Method)))
	if c.ps.password != "" {
		fmt.Fprintf(zbuf, "&password=%s", c.ps.password)
	}
	fmt.Fprint(zbuf, "&headers=")
	for k, v := range r.Header {
		fmt.Fprint(zbuf, hex.EncodeToString([]byte(fmt.Sprintf("%s:%s\r\n", k, v[0]))))
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	payload := hex.EncodeToString(body)
	fmt.Fprintf(zbuf, "&payload=%s", payload)
	zbuf.Close()

	// fetch request
	req, err := http.NewRequest("POST", c.ps.path, buf)
	if err != nil {
		if err != nil {
			log.Printf("NewRequest error: %s", err)
		}
		return err
	}
	req.Host = c.ps.appid + ".appspot.com"
	req.URL.Scheme = "http"

	// fetch
	resp, err := c.ps.t.RoundTrip(req)
	if err != nil {
		if err != nil {
			log.Printf("RoundTrip error: %s", err)
		}
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err := errors.New("resp status error")
		log.Printf("%s", err)
		return err
	}

	// read response
	bodyr := bufio.NewReader(resp.Body)
	compressed, err := bodyr.ReadByte()
	if err != nil {
		log.Printf("Read compressed byte error: %s", err)
		return err
	}
	var status, lenHeaderEncoded, lenContent uint32
	var bodyReader io.Reader
	if compressed == '1' {
		bodyReader, err = zlib.NewReader(bodyr)
		if err != nil {
			log.Printf("zlib.NewReader: ", err)
			return err
		}
		defer bodyReader.(io.ReadCloser).Close()
	} else {
		bodyReader = bodyr
	}
	err = binary.Read(bodyReader, binary.BigEndian, &status)
	if err != nil {
		log.Printf("read status error: %s", err)
		return err
	}
	err = binary.Read(bodyReader, binary.BigEndian, &lenHeaderEncoded)
	if err != nil {
		log.Printf("read lenHeaderEncoded error: %s", err)
		return err
	}
	err = binary.Read(bodyReader, binary.BigEndian, &lenContent)
	if err != nil {
		log.Printf("read lenContent error: %s", err)
		return err
	}
	var _ = lenContent
	bHeaderEncoded := make([]byte, lenHeaderEncoded)
	_, err = io.ReadFull(bodyReader, bHeaderEncoded)
	if err != nil {
		log.Printf("read bHeaderEncoded error: %s", err)
		return err
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", int(status), http.StatusText(int(status)))
	for _, h := range bytes.Split(bHeaderEncoded, []byte{'&'}) {
		kv := bytes.SplitN(h, []byte{'='}, 2)
		if len(kv) != 2 {
			continue
		}
		value := make([]byte, hex.DecodedLen(len(kv[1])))
		_, err := hex.Decode(value, kv[1])
		if err != nil {
			log.Printf("%s %s", kv[0], kv[1])
			log.Printf("decode hex error: %s", err)
			return err
		}
		fmt.Fprintf(w, "%s: %s\r\n", bytes.Title(kv[0]), value)
	}
	fmt.Fprintf(w, "Content-Length: %d\r\n", int(lenContent))
	fmt.Fprintf(w, "\r\n")
	_, err = io.Copy(w, bodyReader)
	if err != nil {
		log.Printf("copy body error: %s", err)
		return err
	}
	err = w.Flush()
	if err != nil {
		log.Printf("body flush error: %s", err)
		return err
	}
	log.Printf("%s \"%s\" %d", r.Method, url, status)
	return nil
}

type ProxyServer struct {
	addr     string
	appid    string
	password string
	path     string
	t        *http.Transport
	certPool *certPool
}

func NewProxyServer(proxyip []string, appid string, password string, path string) *ProxyServer {
	ps := &ProxyServer{appid: appid, password: password, path: path, certPool: newCertPool()}
	ps.t = new(http.Transport)
	ps.t.MaxIdleConnsPerHost = 20
	ps.t.Dial = func(network, addr string) (c net.Conn, err error) {
		ip := proxyip[rand.Intn(len(proxyip))]
		c, err = net.Dial("tcp", ip+":80")
		return
	}
	return ps
}

func (ps *ProxyServer) SetMaxConns(n int) {
	ps.t.MaxIdleConnsPerHost = n
}

func (ps *ProxyServer) Serve(l net.Listener) error {
	defer l.Close()
	for {
		rw, err := l.Accept()
		if err != nil {
			return err
		}
		c := newConn(rw, ps)
		go c.serve()
	}
	return nil
}

func (ps *ProxyServer) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ps.addr = addr
	return ps.Serve(l)
}

func (ps *ProxyServer) Addr() string {
	return ps.addr
}
