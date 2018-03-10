package main

import (
	"crypto/x509"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"bufio"
	"fmt"
)

var logger *log.Logger
var config = loadConfig()

type AutosignConfig struct {
	AutosignChallenge string `yaml:"autosign"`
	LogFile           string `yaml:"logfile"`
}
func info(msg string, int interface{}) {
	logger.Printf(msg,int)
}
func check_error(err error){
	if err != nil {
		fmt.Errorf("An error has occured, halting: %s", err)
		panic(err)
	}
}

func loadConfig() AutosignConfig {
	t := AutosignConfig{}
	autosign, _ := ioutil.ReadFile("/etc/puppetlabs/puppet/autosign.yaml")
	if err := yaml.Unmarshal([]byte(autosign), &t); err != nil {
		logger.Fatalf("Unable to read config file;\n%s", err)
	}
	if t.LogFile == "" {
		t.LogFile = "/var/log/puppetlabs/autosign.log"
	}
	return t
}

func readCert() []byte {
	fileIn := os.Stdin
	if fileIn != nil {
		cert, err := ioutil.ReadFile(fileIn.Name())
		check_error(err)
		return cert
	}
	return []byte{}
}

func createLogger() {
	f, err := os.Create(config.LogFile)
	check_error(err)
	writer := bufio.NewWriter(f)
	logger = log.New(writer, "[autosign]",0)
}

func main() {
	hostname := os.Args[0]
	createLogger()
	info("Checking certificate for %s", hostname)
	cert := readCert()
	x509.ParseCertificateRequest(cert)

}
