package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"runtime"
)

const (
	Version = "v0.3.2"
)

var configFile *string = flag.String("c", "config.xml", "config file")
var config = &Config{}
var CACert *x509.Certificate
var CAKey *rsa.PrivateKey

func testGAE(ips []string, appid string) []string {
	var available []string
	for _, ip := range ips {
		conn, err := net.Dial("tcp", ip+":80")
		if err != nil {
			continue
		}
		fmt.Fprintf(conn, "GET /fetch.py HTTP/1.1\r\nHost: %s.appspot.com\r\n\r\n", appid)
		r := bufio.NewReader(conn)
		line, _, err := r.ReadLine()
		if err != nil {
			continue
		}
		if string(line) != "HTTP/1.1 200 OK" {
			continue
		}
		available = append(available, ip)
		conn.Close()
	}
	return available
}

func main() {
	flag.Parse()
	fmt.Println("+-----------------------------------+")
	fmt.Printf("|     GoAgent (golang)  %s      |\n", Version)
	fmt.Println("+-----------------------------------+")
	fmt.Println()
	fmt.Printf("Loading Config[%s]...", *configFile)
	err := LoadConfig(*configFile, config)
	exitonerr(err)
	if config.LOCAL.NUMCPU <= 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		runtime.GOMAXPROCS(config.LOCAL.NUMCPU)
	}
	fmt.Println("\t[OK]")
	fmt.Printf("Loading Cert...")
	CACert, err = LoadCACert(config.LOCAL.CertFile)
	exitonerr(err)
	fmt.Println("\t\t\t[OK]")
	fmt.Printf("Loading Key...")
	CAKey, err = LoadCAKey(config.LOCAL.KeyFile)
	exitonerr(err)
	fmt.Println("\t\t\t[OK]")
	var ips []string
	if config.Gae.TestGoogleCNIP {
		fmt.Print("Testing GAE IPs...")
		ips = testGAE(config.Gae.GoogleCNIP, config.Gae.Appid)
		if len(ips) > 0 {
			fmt.Println("\t\t[OK]")
		} else {
			fmt.Println("\t\t[Fail]")
			fmt.Println("No IP available. Exit.")
			return
		}
	} else {
		ips = config.Gae.GoogleCNIP
	}
	server := NewProxyServer(ips, config.Gae.Appid, config.Gae.Password, config.Gae.Path)
	server.SetMaxConns(config.LOCAL.MAXCONNS)
	fmt.Printf("Listen on addr [%s]...\n", config.Listen.Addr)
	err = server.ListenAndServe(config.Listen.Addr)
	exitonerr(err)
}
