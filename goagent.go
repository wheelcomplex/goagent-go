package main

import (
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"runtime"
)

const (
	Version = "v0.3.3"
)

var configFile *string = flag.String("c", "config.xml", "config file")
var config = &Config{}
var CACert *x509.Certificate
var CAKey *rsa.PrivateKey

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
	server := NewProxyServer(config.Gae.GoogleCNIP, config.Gae.Appid, config.Gae.Password, config.Gae.Path)
	server.SetMaxConns(config.LOCAL.MAXCONNS)
	fmt.Printf("Listen on addr [%s]...\n", config.Listen.Addr)
	err = server.ListenAndServe(config.Listen.Addr)
	exitonerr(err)
}
