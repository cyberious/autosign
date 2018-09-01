package main

import (
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"github.com/cyberious/autosign/cert"
	"io/ioutil"
)

var (
	subjectNameOid = asn1.ObjectIdentifier{2, 5, 29, 17}
	dnsAltNames    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	debug          = false
)

func init() {
	defaultAutosignConfigFiles := []string{"/etc/puppetlabs/puppet/autosign.json", "/etc/puppetlabs/puppet/autosign.yaml", "autosign.json", "autosign.yaml"}
	flag.String("config", strings.Join(defaultAutosignConfigFiles, ","), "Config files to parse for")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")

}

func isDebug() bool {

	return debug
}

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Println("No hostname was parsed so nothing to test")
		os.Exit(1)
	}

	hostname := flag.Args()[0]
	if f := flag.CommandLine.Lookup("-help"); f != nil {
		fmt.Printf("server set to %#v\n", f)
		flag.PrintDefaults()
		os.Exit(0)
	}

	fmt.Printf("Autosign initiated for hostname %s\n", hostname)
	configFlag := flag.Lookup("config")
	autosignConfig := NewAutosignConfig(strings.Split(configFlag.Value.String(), ","))
	logger := createLogger(autosignConfig)
	autoSignCert := Autosign{Hostname: hostname, Logger: logger, Config: autosignConfig}
	if crt, err := readCert(); err != nil {
		logger.Error(err, "An error has occured, halting: %s", err)
		panic(err)
	} else {
		autoSignCert.CertificateRequest = crt
		shouldSignCert(autoSignCert)
	}
}

func shouldSignCert(as Autosign) {
	fmt.Printf("Autosign for %s \n", as.Hostname)
	if flag.Parsed() && isDebug() {
		fmt.Println("Parsed arguments")
		////fmt.Printf("Config files for %s\n", as.Confi)
		//fmt.Printf("Debug set to %b\n", isDebug)
	}

	as.Logger.Info("Checking certificate for %s \n", as.Hostname)

	if match, err := as.AutosignChallengMatch(); err != nil {
		as.Logger.Error(err, "An error was raised during Autosign Challenge Match")
	} else {
		if match {
			as.Logger.Info("A match was found for Autosign challenge for host %s", as.Hostname)
			os.Exit(0)
		} else {
			as.Logger.Info("Certificate does not match requirements\n")
		}
	}
	if as.HostnameMatch() {
		as.Logger.Info("A match was found for Autosign challenge for hostname pattern %s", as.Hostname)
		os.Exit(0)
	}
}

func readCert() (*cert.PuppetCertificateRequest, error) {
	fileIn := os.Stdin
	if fileIn == nil {
		return nil, errors.New("No file was piped in, we should exit as a result, nothing to assert")
	}
	if certBytes, err := ioutil.ReadFile(fileIn.Name()); err != nil {
		return nil, errors.New("Unable to read cert from stdin")
	} else {
		return cert.NewPuppetCertificateRequest(certBytes)
	}
}
