package main

import (
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"github.com/cyberious/autosign/cert"
	"io/ioutil"
	"os"
	"strings"
)

var (
	subjectNameOid = asn1.ObjectIdentifier{2, 5, 29, 17}
	dnsAltNames    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	debug          = false
	certFile       string
	logger         autosignLogger
)

func init() {
	defaultAutosignConfigFiles := []string{"/etc/puppetlabs/puppet/autosign.json", "/etc/puppetlabs/puppet/autosign.yaml", "autosign.json", "autosign.yaml"}
	flag.String("config", strings.Join(defaultAutosignConfigFiles, ","), "Config files to parse for")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.StringVar(&certFile, "cert", "", "Certificate file to test")
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

	fmt.Printf("autosign initiated for hostname %s\n", hostname)
	configFlag := flag.Lookup("config")
	autosignConfig, err := NewAutosignConfig(strings.Split(configFlag.Value.String(), ","))
	if err != nil {

	}
	logger := createLogger(autosignConfig)
	autoSignCert := autosign{Hostname: hostname, Logger: logger, Config: autosignConfig}

	if crt, err := readCert(hostname); err != nil {
		logger.Error(err, "An error has occured, halting: %s", err)
		panic(err)
	} else {
		autoSignCert.CertificateRequest = crt
		if debug {
			autoSignCert.LogCertDetails()
		}
		shouldSignCert(autoSignCert)
	}
}

func shouldSignCert(as autosign) {
	fmt.Printf("autosign for %s \n", as.Hostname)
	if flag.Parsed() && isDebug() {
		fmt.Println("Parsed arguments")
	}

	as.Logger.Info("Checking certificate for %s \n", as.Hostname)

	if match, err := as.AutosignChallengMatch(); err != nil {
		as.Logger.Error(err, "An error was raised during autosign Challenge Match")
	} else {
		if match {
			if as.CertificateRequest.HasDNSNames() {
				signCertificateRequest(as.CertificateRequest.Hostname)
			}
			as.Logger.Info("A match was found for autosign challenge for host %s", as.Hostname)
			os.Exit(0)
		} else {
			as.Logger.Info("Certificate does not match requirements\n")
		}
	}
	if as.HostnameMatch() {
		as.Logger.Info("A match was found for autosign challenge for hostname pattern %s", as.Hostname)
		os.Exit(0)
	}
}

func readCert(hostname string) (*cert.PuppetCertificateRequest, error) {
	var fileIn *os.File
	if certFile != "" {
		var err error
		fileIn, err = os.Open(certFile)
		if err != nil {
			return nil, err
		}
	} else {
		fileIn = os.Stdin
	}

	if fileIn == nil {
		return nil, errors.New("No file was piped in, we should exit as a result, nothing to assert")
	}
	certBytes, err := ioutil.ReadFile(fileIn.Name())
	if err != nil {
		return nil, errors.New("Unable to read cert from stdin")
	}

	return cert.NewPuppetCertificateRequest(certBytes, hostname)
}
