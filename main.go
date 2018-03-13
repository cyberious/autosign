package main

import (
	"crypto/x509"

	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/cyberious/autosign/x509utils"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
)

var logger *log.Logger
var config AutosignConfig

var subjectNameOid = asn1.ObjectIdentifier{2, 5, 29, 17}
var dnsAltNames = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

const configFile = "/etc/puppetlabs/puppet/autosign.yaml"
const logFile = "puppetlabs-autosign.log"

type AutosignConfig struct {
	AutosignChallenge string   `yaml:"challengePassword"`
	AutosignPatterns  []string `yaml:"autosignPatterns"`
	LogFile           string   `yaml:"logFile"`
}

func logInfo(msg string, int ...interface{}) {
	fmt.Printf(msg, int...)
	logger.Printf(msg, int...)
}
func logError(err error, msg string, int ...interface{}) {
	fmt.Errorf(msg, int...)
	logger.Fatal(err)
}

func pickFile(file1 string, file2 string) string {
	if fileExists(file1) {
		return file1
	}
	if fileExists(file2) {
		return file2
	}
	return ""
}

func checkError(err error) {
	if err != nil {
		logError(err, "An error has occured, halting: %s", err)
		panic(err)
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func loadConfig() AutosignConfig {
	t := AutosignConfig{LogFile: logFile}
	configYaml := pickFile(configFile, "autosign.yaml")
	if configYaml != "" {
		autosign, err := ioutil.ReadFile(configYaml)
		yaml.Unmarshal(autosign, &t)
		fmt.Printf("Loaded config map of:\n\tPatterns: %s\n\tLogfile: %s\n\tChallenge: %s\n", t.AutosignPatterns, t.LogFile, t.AutosignChallenge)
		if err != nil {
			if err := yaml.Unmarshal([]byte(autosign), &t); err != nil {
				logger.Fatalf("Unable to read config file;\n%s", err)
			}
		}
	} else {
		fmt.Println("Unable to read file %s", configYaml)
	}
	fmt.Printf("Loaded config file %s, with values %s \n", configYaml, t)
	return t
}

func readCert() []byte {
	fileIn := os.Stdin
	if fileIn != nil {
		cert, err := ioutil.ReadFile(fileIn.Name())
		checkError(err)
		return cert
	}
	return []byte{}
}

func createLogger() {
	fmt.Println("Creating log")
	f, err := os.Create(config.LogFile)
	checkError(err)
	writer, err := os.OpenFile(f.Name(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Errorf("error opening file: %v", err)
	}
	defer f.Close()
	logger = log.New(writer, "[autosign]", 1)
}

func logCertDetails(cr *x509.CertificateRequest) {
	for i, name := range cr.Subject.Names {
		logInfo("Name %d: \n\tType: %s\n\tValue: %s\n", i, name, name.Value)
	}
	logInfo("Subject: %s \nDNSNames: %s\n", cr.Subject.Names, cr.DNSNames)
	logInfo("Extensions: \n")
	for i, ext := range cr.Extensions {
		if len(ext.Value) != 0 {
			logInfo("\t%d: %s\n", i, ext)
		}
	}
}

func hostnameMatch(hostname string, config AutosignConfig) bool {
	for _, pattern := range config.AutosignPatterns {
		logInfo("Checking pattern '%s'\n", pattern)
		posixRegex, err := regexp.CompilePOSIX(pattern)
		if err != nil {
			logInfo("Failed to compile pattern %s\n\t%s\n", pattern, err)
		} else {
			if posixRegex.MatchString(hostname) {
				logInfo("Matching pattern %s for Hostname %s\n", pattern, hostname)
				return true /* return on first match */
			}
		}
	}
	logInfo("Do not sign %s Failed to match any pattern\n", hostname)
	return false
}
func main() {
	hostname := os.Args[1]
	fmt.Printf("Autosign for %s and config file %s\n", hostname, configFile)
	config = loadConfig()
	createLogger()
	logInfo("Checking certificate for %s \n", hostname)
	cert := readCert()
	pemCert, _ := pem.Decode(cert)
	cr, err := x509.ParseCertificateRequest(pemCert.Bytes)
	cr.Extensions = getPuppetExtensions()
	if err != nil {
		logError(err, "Failed to parse certificate request for %s:\n\t%s \n", hostname, err)
		panic(err)
	}
	logCertDetails(cr)
	if len(cr.DNSNames) == 0 {
		logInfo("No DNS Alt Names\n")
		if len(config.AutosignPatterns) == 0 {
			logInfo("Signing cert for %s: Reason, NO DNS Alt Names matches no pattern match set \n", hostname)
			os.Exit(0)
		} else {
			if hostnameMatch(hostname, config) {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
	}
	if config.AutosignChallenge != "" {
		pass, err := x509utils.ParseChallengePassword(pemCert.Bytes)
		if err != nil {
			logError(err, "Error occurred trying to parse challengePassword for %s \n", hostname)
		}
		logInfo("Checking to see if password\n")
		if pass == config.AutosignChallenge {
			logInfo("Challenge password accepted")
			app := "/opt/puppetlabs/bin/puppet"
			args := []string{"cert", "sign", hostname, "--allow-dns-alt-names", "--ssldir", "/etc/puppetlabs/puppet/ssl"}
			cmd := exec.Command(app, args...)
			err = cmd.Run()
			if err != nil {
				logError(err, "Failed to run command %s\n", cmd.Args)
			}
			err = cmd.Wait()
			logInfo("Output from command %s", os.Stdout)
			os.Exit(0)
		}

		os.Exit(1)
	}
}
