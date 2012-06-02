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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	errResponse502 = fmt.Errorf("server response 502")
)

var (
	rangereq  *regexp.Regexp
	rangeresp *regexp.Regexp
)

func init() {
	var err error
	rangereq, err = regexp.Compile("bytes=(.*)-(.*)")
	if err != nil {
		panic(err)
	}
	rangeresp, err = regexp.Compile("bytes (.*)-(.*)/(.+)")
	if err != nil {
		panic(err)
	}
}

func writeResponse(w io.Writer, resp *http.Response) error {
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)
	if err != nil {
		return fmt.Errorf("writeResponse(send status)>%s", err)
	}
	err = resp.Header.Write(w)
	if err != nil {
		return fmt.Errorf("writeResponse(send header)>%s", err)
	}
	_, err = fmt.Fprintf(w, "\r\n")
	if err != nil {
		return fmt.Errorf("writeResponse(send header end)>%s", err)
	}
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("writeResponse(send body)>%s", err)
	}
	return nil
}

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
	c.bw = bufio.NewWriterSize(c.rw, 1000)
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
			} else if strings.Contains(err.Error(), "connection reset by peer") {
				return
			}
			log.Printf("conn.serve: %s", err)
			return
		}
		if req.Method == "CONNECT" {
			host := strings.SplitN(req.URL.Host, ":", 2)[0]
			cert, err := c.ps.certPool.getCert(host)
			if err != nil {
				log.Printf("conn.serve>%s", err)
				return
			}
			config := &tls.Config{Certificates: []tls.Certificate{*cert}}
			_, err = c.bw.WriteString("HTTP/1.0 200 OK\r\n\r\n")
			if err != nil {
				log.Printf("conn.serve(write status)>%s", err)
				return
			}
			err = c.bw.Flush()
			if err != nil {
				log.Printf("conn.serve(c.bw.Flush)>%s", err)
				return
			}
			c.rw = tls.Server(c.rw, config)
			c.br = bufio.NewReader(c.rw)
			c.bw = bufio.NewWriter(c.rw)
			c.url = "https://" + host
			continue
		}
		err = c.handle(c.bw, req)
		if err != nil {
			if strings.Contains(err.Error(), "broken pipe") {
				return
			}
			log.Printf("conn.serve>%s", err)
			return
		}
	}
	panic("not reach")
}

func (c *conn) packRequest(r *http.Request) (*http.Request, error) {
	buf := &bytes.Buffer{}
	zbuf, err := zlib.NewWriterLevel(buf, zlib.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("conn.packRequest(zlib.NewWriterLevel)>%s", err)
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
		return nil, fmt.Errorf("conn.packRequest(ioutil.ReadAll(r.Body))>%s", err)
	}
	payload := hex.EncodeToString(body)
	fmt.Fprintf(zbuf, "&payload=%s", payload)
	zbuf.Close()
	req, err := http.NewRequest("POST", c.ps.path, buf)
	if err != nil {
		return nil, fmt.Errorf("conn.packRequest(http.NewRequest)>%s", err)
	}
	req.Host = c.ps.appid[rand.Intn(len(c.ps.appid))] + ".appspot.com"
	req.URL.Scheme = "http"
	return req, nil
}

func (c *conn) unpackResponse(resp *http.Response) (*http.Response, error) {
	// read response
	bodyr := bufio.NewReader(resp.Body)
	compressed, err := bodyr.ReadByte()
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("conn.unpackResponse(bodyr.ReadByte)>%s", err)
	}
	var status, lenHeaderEncoded, lenContent uint32
	var bodyReader io.ReadCloser
	if compressed == '1' {
		bodyReader, err = zlib.NewReader(bodyr)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("conn.unpackResponse(zlib.NewReader)>%s", err)
		}
		bodyReader = &closeWrap{closer: resp.Body, ReadCloser: bodyReader}
	} else {
		bodyReader = &closeWrap{closer: resp.Body, ReadCloser: ioutil.NopCloser(bodyr)}
	}

	// deal with header
	err = binary.Read(bodyReader, binary.BigEndian, &status)
	if err != nil {
		bodyReader.Close()
		return nil, fmt.Errorf("conn.unpackResponse(read status)>%s", err)
	}
	err = binary.Read(bodyReader, binary.BigEndian, &lenHeaderEncoded)
	if err != nil {
		bodyReader.Close()
		return nil, fmt.Errorf("conn.unpackResponse(read lenHeaderEncoded)>%s", err)
	}
	err = binary.Read(bodyReader, binary.BigEndian, &lenContent)
	if err != nil {
		bodyReader.Close()
		return nil, fmt.Errorf("conn.unpackResponse(read lenContent)>%s", err)
	}
	response := new(http.Response)
	response.StatusCode = int(status)
	response.Status = http.StatusText(int(status))
	response.ProtoMajor = 1
	response.ProtoMinor = 0
	bHeaderEncoded := make([]byte, lenHeaderEncoded)
	_, err = io.ReadFull(bodyReader, bHeaderEncoded)
	if err != nil {
		bodyReader.Close()
		return nil, fmt.Errorf("conn.unpackResponse(read header)>%s", err)
	}
	response.Header = make(http.Header)
	for _, h := range strings.Split(string(bHeaderEncoded), "&") {
		kv := strings.SplitN(h, "=", 2)
		if len(kv) != 2 {
			continue
		}
		value, err := hex.DecodeString(kv[1])
		if err != nil {
			bodyReader.Close()
			return nil, fmt.Errorf("conn.unpackResponse(hex.DecodeString(kv[1]))>%s", err)
		}
		if strings.Title(kv[0]) == "Set-Cookie" {
			for _, cookie := range strings.Split(string(value), "\r\nSet-Cookie: ") {
				response.Header.Add("Set-Cookie", cookie)
			}
		} else {
			response.Header.Add(strings.Title(kv[0]), string(value))
		}
	}
	response.Header.Set("Content-Length", strconv.Itoa(int(lenContent)))
	response.Body = bodyReader
	return response, nil
}

func (c *conn) rangeRoundTrip(r *http.Request, start int, end int) (response *http.Response, start_out int, end_out int, length_out int, err error) {
	r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	response, err = c.roundTrip(r)
	if err != nil {
		err = fmt.Errorf("conn.rangeRoundTrip>%s", err)
		return
	}
	if response.StatusCode != 206 {
		err = errors.New("conn.rangeRoundTrip: wrong range status code")
		return
	}
	contentRange := response.Header.Get("Content-Range")
	if contentRange == "" {
		err = errors.New("conn.rangeRoundTrip: empty content range")
		return
	}
	m := rangeresp.FindStringSubmatch(contentRange)
	if len(m) != 4 {
		err = errors.New("conn.rangeRoundTrip: invalid content range")
		return
	}
	start_out, err = strconv.Atoi(m[1])
	if err != nil {
		err = fmt.Errorf("conn.rangeRoundTrip(convert start)>%s", err)
		return
	}
	end_out, err = strconv.Atoi(m[2])
	if err != nil {
		err = fmt.Errorf("conn.rangeRoundTrip(convert end)>%s", err)
		return
	}
	length_out, err = strconv.Atoi(m[3])
	if err != nil {
		err = fmt.Errorf("conn.rangeRoundTrip(convert length)>%s", err)
		return
	}
	return
}

func (c *conn) largefetch(w *bufio.Writer, r *http.Request, first *http.Response) error {
	pos := 0
	length := 0
	step := 100000
	var err error
	if first == nil {
		first, _, pos, length, err = c.rangeRoundTrip(r, 0, 1000000)
		if err != nil {
			return fmt.Errorf("conn.largefetch(first roundtrip): %s", err)
		}
		defer first.Body.Close()
	} else {
		contentRange := first.Header.Get("Content-Range")
		if contentRange == "" {
			return errors.New("conn.largefetch: empty content range")
		}
		m := rangeresp.FindStringSubmatch(contentRange)
		if len(m) != 4 {
			return errors.New("conn.largefetch: invalid content range")
		}
		pos, err = strconv.Atoi(m[2])
		if err != nil {
			return fmt.Errorf("conn.largefetch(convert pos)>%s", err)
		}
		length, err = strconv.Atoi(m[3])
		if err != nil {
			return fmt.Errorf("conn.largefetch(convert length)>%s", err)
		}
	}
	first.Header.Del("Content-Range")
	//first.ContentLength = int64(end - start + 1)
	first.Header.Set("Content-Length", strconv.Itoa(length))
	first.StatusCode = 200
	first.Status = http.StatusText(200)
	err = writeResponse(w, first)
	if err != nil {
		return fmt.Errorf("conn.largefetch>%s", err)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("conn.largefetch(w.Flush)>%s", err)
	}
	if length-pos-1 == 0 {
		return nil
	}
	var seq sequencer
	task := make(chan int)
	errChan := make(chan error)
	var threadcount int32
	for i := 0; i < 30; i++ {
		go func() {
			atomic.AddInt32(&threadcount, 1)
			defer atomic.AddInt32(&threadcount, -1)
			for n := range task {
				start_in := pos + 1 + step*n
				end_in := pos + step*(n+1)
				if end_in > length-1 {
					end_in = length - 1
				}
				var start_out, end_out int
				var resp *http.Response
				var err error
				for i := 0; i < 3; i++ {
					resp, start_out, end_out, _, err = c.rangeRoundTrip(r, start_in, end_in)
					if err == nil {
						break
					}
				}
				if err != nil {
					errChan <- fmt.Errorf("conn.largefetch.routine>%s", err)
					seq.Close()
					return
				}
				if start_out != start_in || end_out != end_in {
					errChan <- errors.New("conn.largefetch.routine: error range returned")
				}
				ok := seq.Start(uint(n))
				if !ok { // seq closed
					return
				}
				_, err = io.Copy(w, resp.Body)
				resp.Body.Close()
				if err != nil {
					errChan <- fmt.Errorf("conn.largefetch.routine(send conts body)>%s", err)
					seq.Close()
					return
				}
				err = w.Flush()
				if err != nil {
					errChan <- fmt.Errorf("conn.largefetch.routine(conts flush)>%s", err)
					seq.Close()
					return
				}
				seq.End(uint(n))
				errChan <- nil
			}
		}()
	}
	var nTask int
OUT2:
	for i := 0; i < (length-pos-2)/step+1; i++ {
	OUT1:
		for {
			select {
			case task <- i:
				nTask++
				break OUT1
			case err0 := <-errChan:
				if err0 != nil {
					err = fmt.Errorf("largefetch>%s", err0)
					close(task)
					nTask--
					break OUT2
				}
				nTask--
			}
		}
	}
	for nTask > 0 {
		err0 := <-errChan
		if err0 != nil && err == nil {
			err = fmt.Errorf("largefetch>%s", err0)
		}
		nTask--
	}
	close(errChan)
	r.Body.Close()
	if atomic.LoadInt32(&threadcount) != 0 {
		panic("goroutine leak")
	}
	return err
}

func (c *conn) handle(w *bufio.Writer, r *http.Request) error {
	response, err := c.roundTrip(r)
	if err != nil {
		if err == errResponse502 && r.Method == "GET" {
			err = c.largefetch(w, r, nil)
			if err != nil {
				return fmt.Errorf("conn.handle>%s", err)
			}
			return nil
		} else {
			return fmt.Errorf("conn.handle>%s", err)
		}
	}
	defer response.Body.Close()
	if response.StatusCode == 206 {
		return c.largefetch(w, r, response)
	}
	r.Body.Close()
	err = writeResponse(w, response)
	if err != nil {
		return fmt.Errorf("conn.handle>%s", err)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("conn.handle(w.Flush)>%s", err)
	}
	return nil
}

func (c *conn) roundTrip(r *http.Request) (*http.Response, error) {
	req, err := c.packRequest(r)
	if err != nil {
		return nil, fmt.Errorf("conn.roundTrip>%s", err)
	}
	resp, err := c.ps.t.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("conn.roundTrip>%s", err)
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 502 {
			return nil, errResponse502
		}
		return nil, fmt.Errorf("conn.roundTrip>status error: %d", resp.StatusCode)
	}
	response, err := c.unpackResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("conn.roundTrip>%s", err)
	}
	return response, nil
}

type ProxyServer struct {
	addr     string
	appid    []string
	password string
	path     string
	t        *http.Transport
	certPool *certPool
}

func NewProxyServer(proxyip []string, appid []string, password string, path string) *ProxyServer {
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
