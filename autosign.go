package main

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"github.com/cyberious/autosign/cert"
	"io/ioutil"
)

var (
	logger         *log.Logger
	autosignConfig AutosignConfig
	configFiles    string
	hostname       string
	debug          bool
	subjectNameOid = asn1.ObjectIdentifier{2, 5, 29, 17}
	dnsAltNames    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

func init() {
	defaultAutosignConfigFiles := []string{"/etc/puppetlabs/puppet/autosign.json", "/etc/puppetlabs/puppet/autosign.yaml", "autosign.json", "autosign.yaml"}
	flag.StringVar(&configFiles, "config", strings.Join(defaultAutosignConfigFiles, ","), "Config files to parse for")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.Parse()
	if len(flag.Args()) > 0 {
		hostname = flag.Args()[0]
	}

}

func main() {
	flag.Parse()
	fmt.Println("Autosign initiated")
	if f := flag.CommandLine.Lookup("-help"); f != nil {
		fmt.Printf("server set to %#v\n", f)
		os.Exit(0)
	}
	if hostname == "" {
		fmt.Println("No hostname was parsed so nothing to test")
		os.Exit(1)
	}

	fmt.Printf("Autosign for %s \n", hostname)
	if flag.Parsed() {
		fmt.Println("Parsed arguments")
		fmt.Printf("Config files for %s\n", configFiles)
		fmt.Printf("Debug set to %b\n", debug)
	}
	autosignConfig = newAutosignConfig(strings.Split(configFiles, ","))
	createLogger()
	logInfo("Checking certificate for %s \n", hostname)
	pcr, err := cert.NewPuppetCertificateRequest(readCert())
	if err != nil {
		logError(err, "Failed to parse certificate request for %s:\n\t%s \n", hostname, err)
		panic(err)
	}
	logCertDetails(pcr.CertRequest)

	if autosignChallengMatch(hostname, pcr, autosignConfig) {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func readCert() []byte {
	fileIn := os.Stdin
	if fileIn != nil {
		cert, err := ioutil.ReadFile(fileIn.Name())
		checkError(err)
		return cert
	} else {
		fmt.Print("No file was piped in, we are exiting as a result, nothing to assert")
		os.Exit(1)
	}
	return []byte{}
}

func checkError(err error) {
	if err != nil {
		logError(err, "An error has occured, halting: %s", err)
		panic(err)
	}
}
