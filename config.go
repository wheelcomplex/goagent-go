package main

import (
	"encoding/xml"
	"errors"
	"os"
)

type GAE struct {
	XMLName        xml.Name `xml:"GAE"`
	Appid          string   `xml:"APPID"`
	Path           string   `xml:"PATH"`
	Password       string   `xml:"PASSWORD"`
	GoogleCNIP     []string `xml:"GOOGLECNIP>IP"`
	TestGoogleCNIP bool     `xml:"TESTGOOGLECNIP"`
}

type LISTEN struct {
	XMLName xml.Name `xml:"LISTEN"`
	Addr    string   `xml:"ADDR"`
}

type LOCAL struct {
	XMLName  xml.Name `xml:"LOCAL"`
	NUMCPU   int      `xml:"NUMCPU"`
	MAXCONNS int      `xml:"MAXCONNS"`
	CertFile string   `xml:"CERTFILE"`
	KeyFile  string   `xml:"KEYFILE"`
}

type Config struct {
	XMLName xml.Name `xml:"GOAGENT"`
	Gae     GAE
	Listen  LISTEN
	LOCAL   LOCAL
}

var DefaultGAE = GAE{Path: "/fetch.py", Appid: "goagent.go"}
var DefaultLISTEN = LISTEN{Addr: ":8087"}
var DefaultConfig = Config{Gae: DefaultGAE, Listen: DefaultLISTEN}

func SaveConfig(filename string, c *Config) error {
	b, err := xml.MarshalIndent(c, "", "\t")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func LoadConfig(filename string, c *Config) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
	err = dec.Decode(c)
	if err != nil {
		return err
	}
	if c.Gae.Appid == "appid" {
		return errors.New("appid not set")
	}
	if c.Gae.Path == "" {
		c.Gae.Path = "/fetch.py"
	}
	if c.LOCAL.CertFile == "" {
		c.LOCAL.CertFile = "CA.crt"
	}
	if c.LOCAL.KeyFile == "" {
		c.LOCAL.KeyFile = "CA.key"
	}
	if c.Listen.Addr == "" {
		c.Listen.Addr = ":8087"
	}
	if c.Gae.GoogleCNIP == nil {
		c.Gae.GoogleCNIP = []string{"203.208.46.1", "203.208.46.2", "203.208.46.3", "203.208.46.4", "203.208.46.5", "203.208.46.6", "203.208.46.7", "203.208.46.8"}
	}
	return nil
}
