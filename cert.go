package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"time"
)

func init() {
	mrand.Seed(time.Now().UnixNano())
}

func LoadCACert(certFile string) (x509Cert *x509.Certificate, err error) {
	certPEMBLOCK, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	certDERBLOCK, _ := pem.Decode(certPEMBLOCK)
	if certDERBLOCK == nil {
		return nil, errors.New("LoadCACert: failed to parse key PEM data")
	}
	if certDERBLOCK.Type != "CERTIFICATE" {
		return nil, errors.New("LoadCACert: wrong certificate type")
	}
	x509Cert, err = x509.ParseCertificate(certDERBLOCK.Bytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, err
}

func LoadCAKey(keyFile string) (key *rsa.PrivateKey, err error) {
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		return nil, errors.New("LoadCAKey: failed to parse key PEM data")
	}

	if key, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err != nil {
		var privKey interface{}
		if privKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err != nil {
			err = errors.New("LoadCAKey: failed to parse key: " + err.Error())
			return
		}
		var ok bool
		if key, ok = privKey.(*rsa.PrivateKey); !ok {
			return nil, errors.New("LoadCAKey: found non-RSA private key in PKCS#8 wrapping")
		}
	}
	return
}

func GenHostCert(CACert *x509.Certificate, CAKey *rsa.PrivateKey, hostName string) (cert *tls.Certificate, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(mrand.Int63()),
		Subject: pkix.Name{
			CommonName:   hostName,
			Organization: []string{"GoAgent CA"},
		},
		NotBefore: now.Add(-5 * time.Minute).UTC(),
		NotAfter:  now.AddDate(1, 0, 0).UTC(), // valid for 1 year.

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, CACert, &priv.PublicKey, CAKey)
	if err != nil {
		return
	}
	cert = new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, derBytes)
	cert.PrivateKey = priv
	return
}
