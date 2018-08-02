package main

import (
	"io/ioutil"
	"log"
			"os"
	"encoding/pem"
	"crypto/x509"
	"strings"
	"fmt"
	"strconv"
	"time"
)

var pathToCertificates = "~/workspace/certificates/sorted_certificates"
var year = 2012
var outputPath = "~/workspace/certificates/" + strconv.Itoa(year)

func main() {
	fmt.Println("Starting certificate classifier")
	files, err := ioutil.ReadDir(pathToCertificates)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("All the certificates in the directory are read")
	fmt.Println("Starting to parse certificates")

	os.Mkdir(outputPath, 0755)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fmt.Println("Certificate being processed:", file.Name())
		var inputFile *os.File
		var err error
		inputFile, err = os.Open(pathToCertificates + file.Name())
		if err != nil {
			log.Fatalf("unable to open file %s: %s", file.Name(), err)
		}
		cert, err := parseCertificateFromFile(inputFile)
		if err == nil {
			if cert.NotBefore.Sub(time.Date(year, time.January, 1, 0,0,0,0, time.UTC)) >= 0 {
				err = os.Rename(pathToCertificates + file.Name(), outputPath + file.Name())
				if err != nil {
					fmt.Println("Failed to move certificate", err)
				}
			}
		}
		inputFile.Close()
	}
}

func parseCertificateFromFile(inputFile *os.File) (x509.Certificate, error) {
	var fileFmt = ""
	if strings.HasSuffix(inputFile.Name(), "pem") {
		fileFmt = "pem"
	}
	if strings.HasSuffix(inputFile.Name(), "der") {
		fileFmt = "der"
	}

	fileBytes, err := ioutil.ReadAll(inputFile)
	if err != nil {
		log.Fatalf("unable to read file %s: %s", inputFile.Name(), err)
	}

	var asn1Data []byte
	switch fileFmt {
	case "pem":
		p, _ := pem.Decode(fileBytes)
		if p == nil || p.Type != "CERTIFICATE" {
			log.Fatal("unable to parse PEM")
		}
		asn1Data = p.Bytes
	case "der":
		asn1Data = fileBytes
	default:
		log.Fatalf("unknown input format %s", fileFmt)
	}

	c, err := x509.ParseCertificate(asn1Data)
	if err == nil {
		return *c, err
	}
	fmt.Println("Unable to parse certificate: ", inputFile.Name())
	return x509.Certificate{}, err
}