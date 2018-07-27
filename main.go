package main

import (
	"io/ioutil"
	"log"
			"os"
	"encoding/pem"
	"crypto/x509"
	"strings"
	"fmt"
)
var years = []string{"2015, 2016, 2017, 2018"}
var months = []string{"january, february, march, april, may, june, july, august, september, october, november, december"}

func main() {
	var pathToCertificates = "./certificates/"
	categorizeByCA(pathToCertificates)
}

func categorizeByCA(pathToCertificates string) {
	files, err := ioutil.ReadDir(pathToCertificates)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		var fileFmt = ""
		if strings.HasSuffix(file.Name(), "pem") {
			fileFmt = "pem"
		}
		if strings.HasSuffix(file.Name(), "der") {
			fileFmt = "der"
		}

		if fileFmt != "" {
			var inputFile *os.File
			var err error
			inputFile, err = os.Open(pathToCertificates + file.Name())
			if err != nil {
				log.Fatalf("unable to open file %s: %s", file.Name(), err)
			}
			nameOfCA, err := findIssuerOfCertificate(inputFile, fileFmt)
			if err == nil {
				os.Mkdir(pathToCertificates + nameOfCA, 0755)
				err = os.Rename(pathToCertificates + file.Name(), pathToCertificates + nameOfCA + "/" + file.Name())
				if err != nil {
					fmt.Println(err)
				}
			}
			inputFile.Close()
		}
	}
}

func findIssuerOfCertificate(inputFile *os.File, fileFmt string) (str string, err error) {
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

	var name = ""
	c, err := x509.ParseCertificate(asn1Data)
	if err == nil {
		name = c.Issuer.Organization[0]
	}
	fmt.Println("Could not extract certificate issuer", err)
	return name, err
}