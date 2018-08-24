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
)

func init() {
	defaultAutosignConfigFiles := []string{"/etc/puppetlabs/puppet/autosign.json", "/etc/puppetlabs/puppet/autosign.yaml", "autosign.json", "autosign.yaml"}
	flag.String("config", strings.Join(defaultAutosignConfigFiles, ","), "Config files to parse for")
	flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

}

func is_debug() bool {
	debugFlag := flag.Lookup("debug")
	if debug, err := strconv.ParseBool(debugFlag.Value); err != nil {
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

	hostname = flag.Args()[0]
	if f := flag.CommandLine.Lookup("-help"); f != nil {
		fmt.Printf("server set to %#v\n", f)
		flag.PrintDefaults()
		os.Exit(0)
	}

	fmt.Printf("Autosign initiated for hostname %s\n", hostname)
	configFlag := flag.Lookup("config")
	autosignConfig := newAutosignConfig(strings.Split(configFlag.Value, ","))
	logger := createLogger(autosignConfig)
	autoSignCert := Autosign{Hostname: hostname, Logger: logger}

	if cert, err := readCert(); err != nil {
		log.Error(err, "An error has occured, halting: %s", err)
		panic(err)
	} else {
		shouldSignCert(hostname, cert, autosignConfig, logger)
	}
}

func shouldSignCert(hostname string, certBytes []byte, config AutosignConfigFile, log *Log) {
	fmt.Printf("Autosign for %s \n", hostname)
	if flag.Parsed() {
		fmt.Println("Parsed arguments")
		fmt.Printf("Config files for %s\n", configFiles)
		fmt.Printf("Debug set to %b\n", is_debug)
	}
	log.Info(logger, "Checking certificate for %s \n", hostname)
	pcr, err := cert.NewPuppetCertificateRequest(certBytes)
	if err != nil {
		logError(err, "Failed to parse certificate request for %s:\n\t%s \n", hostname, err)
		panic(err)
	}
	//logCertDetails(pcr.CertRequest)

	if autosignChallengMatch(hostname, pcr, config) {
		os.Exit(0)
	} else {
		logInfo("Certificate does not match requirements, should not sign, exit code (1)\n")
		os.Exit(1)
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
