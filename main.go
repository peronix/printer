package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/karalabe/gousb/usb"
)

var (
	port     = 8888
	certfile = "cert.pem"
	keyfile  = "key.pem"
)

const (
	BOCA_SYSTEMS = "0a43"
)

type Printer struct {
	Vendor        string       `json:"vendor"`
	Product       string       `json:"product"`
	Name          string       `json:"name"`
	Device        *usb.Device  `json:"-"`
	WriteEndpoint usb.Endpoint `json:"-"`
}

var printers map[string]*Printer

func listHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "inline")
	b, err := json.Marshal(printers)
	if err != nil {
		io.WriteString(w, "error serializing printer list")
		return
	}
	io.WriteString(w, string(b))
}

func cmdHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	pkey := r.FormValue("printer")
	if len(pkey) == 0 {
		io.WriteString(w, "param 'printer' is missing")
		return
	}
	command := r.FormValue("command")
	if len(command) == 0 {
		io.WriteString(w, "param 'command' is missing")
		return
	}
	printer, ok := printers[pkey]
	if !ok {
		io.WriteString(w, "printer not found")
		return
	}
	_, err := printer.WriteEndpoint.Write([]byte(command))
	if err != nil {
		io.WriteString(w, err.Error())
		return
	}
	io.WriteString(w, "OK")
}

func main() {
	var err error
	ctx, err := usb.NewContext()
	if nil != err {
		log.Printf("error opening usb context: %s", err)
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	quit := make(chan struct{})
	go func() {
		err := findPrinters(ctx)
		if nil != err {
			log.Printf("error reading from usb context: %s", err)
			return
		}
		for {
			select {
			case <-ticker.C:
				findPrinters(ctx)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	defer func() {
		close(quit)
		for _, printer := range printers {
			printer.Device.Close()
		}
		ctx.Close()
	}()
	_, err = tls.LoadX509KeyPair("./"+certfile, "./"+keyfile)
	if err != nil {
		err = generateCertKeyPair()
		if err != nil {
			log.Fatalf("error generating self signed cert: %s", err)
			return
		}
		_, err = tls.LoadX509KeyPair("./"+certfile, "./"+keyfile)
		if err != nil {
			log.Fatalf("error loading cert/key pair: %s", err)
			return
		}
	}

	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/cmd", cmdHandler)
	log.Printf("listening on port %v", port)
	err = http.ListenAndServeTLS("localhost:8888", "./"+certfile, "./"+keyfile, nil)
	if err != nil {
		log.Fatalf("ListenAndServeTLS: %s", err)
	}
}

func findPrinters(ctx *usb.Context) error {
	devices, err := ctx.ListDevices(func(desc *usb.Descriptor) bool {
		switch desc.Vendor.String() {
		// Boca Systems, Inc.
		case BOCA_SYSTEMS:
			return true
		}
		return false
	})
	if nil != err {
		return err
	}
	p := make(map[string]*Printer)
	for _, device := range devices {
		pkey := fmt.Sprintf("%s-%s", device.Vendor.String(), device.Product.String())
		if printer, ok := printers[pkey]; ok {
			p[pkey] = printer
		} else {
			printer := &Printer{
				Vendor:  device.Vendor.String(),
				Product: device.Product.String(),
				Device:  device,
			}
			switch printer.Vendor {
			case BOCA_SYSTEMS:
				endpoint, err := printer.Device.OpenEndpoint(1, 0, 0, 0x01)
				if err != nil {
					println(err.Error())
					continue
				}
				printer.WriteEndpoint = endpoint
				n1, _ := device.GetStringDescriptor(1)
				n2, _ := device.GetStringDescriptor(2)
				printer.Name = n1 + " " + n2
			}
			println(pkey + ": " + printer.Name + " connected")
			p[pkey] = printer
		}
	}
	for pkey, printer := range printers {
		if _, ok := p[pkey]; !ok {
			println(pkey + ": " + printer.Name + " disconnected")
			printer.Device.Close()
		}
	}
	printers = p
	return err
}

func generateCertKeyPair() error {
	var priv *rsa.PrivateKey
	var err error

	dir, err := os.Getwd()
	if err != nil {
		os.Remove(certfile)
		os.Remove(keyfile)
		return err
	}

	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	notAfter := time.Now().Add(20 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Webconnex"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certfile)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		os.Remove(certfile)
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	time.Sleep(time.Second)

	// add cert to trusted root CAs
	if runtime.GOOS == "windows" {
		certpath := dir + "\\" + certfile
		err = exec.Command("cmd", "/c", "certutil", "-addstore", "root", certpath).Run()
	} else {
		certpath := dir + "/" + certfile
		err = exec.Command("/bin/sh", "-c", `sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "`+certpath+`"`).Run()
	}
	if err != nil {
		os.Remove(certfile)
		os.Remove(keyfile)
		return err
	}

	return nil
}
