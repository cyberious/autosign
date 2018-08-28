package main

import (
	"github.com/cyberious/autosign/cert"
	"os/exec"
	"os"
	"fmt"
	"regexp"
)

type Autosign struct {
	Hostname           string
	Config             AutosignConfig
	CertificateRequest cert.PuppetCertificateRequest
	Logger             *Log
}

func (a *Autosign) AutosignChallengMatch() (bool, error) {
	if a.Config.AutosignChallenge != "" && a.CertificateRequest.HasPassword() {
		if match, err := a.CertificateRequest.PasswordMatch(a.Config.AutosignChallenge); err != nil {
			a.Logger.Error(err, "Error occurred trying to parse challengePassword for %s \n", a.Hostname)
			return false, err
		} else {
			a.Logger.Info("Checking to see if password\n")
			return match, nil
		}
	}
	return false, nil
}

func (a *Autosign) DnsAltNameMatch() (bool, error) {
	return false, nil
}

func (a *Autosign) LogCertDetails() {

}

func (a *Autosign) HostnameMatch() (bool) {
	a.Logger.Info("Begining hostnamematch for %s\n", a.Hostname)
	for _, pattern := range a.Config.AutosignPatterns {
		a.Logger.Info("Checking pattern '%s'\n", pattern)
		posixRegex, err := regexp.Compile(pattern)
		if err != nil {
			a.Logger.Info("Failed to compile pattern %s\n\t%s\n", pattern, err)
		} else {
			if posixRegex.MatchString(a.Hostname) {
				a.Logger.Info("Matching pattern %s for Hostname %s\n", pattern, a.Hostname)
				return true /* return on first match */
			}
		}
	}
	a.Logger.Info("Do not sign %s Failed to match any pattern\n", a.Hostname)
	return false
}

func (a *Autosign) CheckDNSAltNamesIfAny() bool {
	return false
}

//
//func logCertDetails(cr *x509.CertificateRequest) {
//	for i, name := range cr.Subject.Names {
//		logInfo("Name %d: \n\tType: %s\n\tValue: %s\n", i, name, name.Value)
//	}
//	logInfo("Subject: %s \nDNSNames: %s\n", cr.Subject.Names, cr.DNSNames)
//	if len(cr.Extensions) > 0 {
//		logInfo("Extensions: \n")
//		for i, ext := range cr.Extensions {
//			if len(ext.Value) != 0 {
//				logInfo("\t%d: %s\n", i, ext)
//			}
//		}
//	}
//}
//
//func hostnameMatch(hostname string, autosignConfig AutosignConfigFile) bool {
//	for _, pattern := range autosignConfig.AutosignPatterns {
//		logInfo("Checking pattern '%s'\n", pattern)
//		posixRegex, err := regexp.Compile(pattern)
//		if err != nil {
//			logInfo("Failed to compile pattern %s\n\t%s\n", pattern, err)
//		} else {
//			if posixRegex.MatchString(hostname) {
//				logInfo("Matching pattern %s for Hostname %s\n", pattern, hostname)
//				return true /* return on first match */
//			}
//		}
//	}
//	logInfo("Do not sign %s Failed to match any pattern\n", hostname)
//	return false
//}
//
//func checkDNSAltNamesIfAny(hostname string, pcr cert.PuppetCertificateRequest, autosignConfig AutosignConfigFile) bool {
//	if !pcr.HasDNSNames() {
//		logInfo("No DNS Alt Names\n")
//		if len(autosignConfig.AutosignPatterns) == 0 {
//			logInfo("Signing cert for %s: Reason, NO DNS Alt Names matches no pattern match set \n", hostname)
//			return true
//		} else {
//			return hostnameMatch(hostname, autosignConfig)
//		}
//	}
//	return false
//}
//
func signCertificateRequest(hostname string) {
	//logInfo("Challenge password accepted")
	app := "/opt/puppetlabs/bin/puppet"
	args := []string{"cert", "sign", hostname, "--allow-dns-alt-names", "--ssldir", "/etc/puppetlabs/puppet/ssl"}
	cmd := exec.Command(app, args...)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("An error occured %s\n", err)
		os.Exit(1)
		//logError(err, "Failed to run command %s\n", cmd.Args)
	}
	err = cmd.Wait()
	//logInfo("Output from command %s", os.Stdout)
}