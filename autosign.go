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
	"strconv"
)

var (
	subjectNameOid = asn1.ObjectIdentifier{2, 5, 29, 17}
	dnsAltNames    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

func init() {
	defaultAutosignConfigFiles := []string{"/etc/puppetlabs/puppet/autosign.json", "/etc/puppetlabs/puppet/autosign.yaml", "autosign.json", "autosign.yaml"}
	flag.String("config", strings.Join(defaultAutosignConfigFiles, ","), "Config files to parse for")
	flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

}
func flagToBool(f *flag.Flag) (bool, error) {
	boolValue, err := strconv.ParseBool(f.Value.String())
	return boolValue, err
}
func is_debug() bool {
	debugFlag := flag.Lookup("debug")
	if debug, err := flagToBool(debugFlag); err != nil {
		return false
	} else {
		return debug
	}
}

func main() {
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
	autosignConfig := newAutosignConfig(strings.Split(configFlag.Value.String(), ","))
	logger := createLogger(autosignConfig)
	autoSignCert := Autosign{Hostname: hostname, Logger: logger, Config: autosignConfig}
	if crt, err := readCert(); err != nil {
		logger.Error(err, "An error has occured, halting: %s", err)
		panic(err)
	} else {
		autoSignCert.CertificateRequest, err = cert.NewPuppetCertificateRequest(crt)
		shouldSignCert(autoSignCert)
	}
}

func shouldSignCert(as Autosign) {
	fmt.Printf("Autosign for %s \n", as.Hostname)
	if flag.Parsed() && is_debug() {
		fmt.Println("Parsed arguments")
		fmt.Printf("Config files for %s\n", as.Config)
		fmt.Printf("Debug set to %b\n", is_debug)
	}

	as.Logger.Info("Checking certificate for %s \n", as.Hostname)
	if certBytes, err := readCert(); err != nil {
		as.Logger.Error(err, "An error occurred reading the cert for %s\n", as.Hostname)
		panic(err)
	} else {
		as.CertificateRequest, err = cert.NewPuppetCertificateRequest(certBytes)
		if err != nil {
			as.Logger.Error(err, "Failed to parse certificate request for %s:\n\t%s \n", as.Hostname, err)
			panic(err)
		}
	}

	if match, err := as.AutosignChallengMatch(); err != nil {
		as.Logger.Error(err, "An error was raised during Autosign Challenge Match")
	} else {
		if match {
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

func readCert() ([]byte, error) {
	fileIn := os.Stdin
	if fileIn == nil {
		return []byte{}, errors.New("No file was piped in, we should exit as a result, nothing to assert")
	}
	if cert, err := ioutil.ReadFile(fileIn.Name()); err != nil {
		return cert, err
	} else {
		return cert, nil
	}
}
