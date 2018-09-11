package main

import (
	"fmt"
	"github.com/cyberious/autosign/cert"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type autosign struct {
	Hostname           string
	Config             *AutosignConfig
	CertificateRequest *cert.PuppetCertificateRequest
	Logger             *autosignLogger
}

func (a *autosign) AutosignChallengMatch() (bool, error) {
	if a.Config.AutosignChallenge != "" && a.CertificateRequest.HasPassword() {
		match, err := a.CertificateRequest.PasswordMatch(a.Config.AutosignChallenge)
		if err != nil {
			a.Logger.Error(err, "Error occurred trying to parse challengePassword for %s \n", a.Hostname)
			return false, err
		}
		a.Logger.Info("Checking to see if password\n")
		return match, nil
	}
	return false, nil
}

func (a *autosign) DNSAltNameMatch() (bool, error) {
	pcr := a.CertificateRequest
	if !pcr.HasDNSNames() {
		a.Logger.Info("No DNS Alt Names\n")
		if len(a.Config.AutosignPatterns) == 0 {
			a.Logger.Info("Signing cert for %s: Reason, NO DNS Alt Names matches and No pattern matches set \n", a.Hostname)
			return true, nil
		}
	} else {
		for _, dnsName := range pcr.DNSNames {
			match, err := HostnameMatch(a.Config, dnsName)
			if match {
				return match, err
			}
		}
	}
	return false, nil
}

func (a *autosign) LogCertDetails() {
	cr := a.CertificateRequest
	for i, name := range cr.Subject.Names {
		a.Logger.Info("Name %d: \n\tType: %s\n\tValue: %s\n", i, name, name.Value)
	}
	a.Logger.Info("Subject: %s \nDNSNames: %s\n", cr.Subject.Names, cr.DNSNames)
	if len(cr.Extensions) > 0 {
		a.Logger.Info("Extensions: \n")
		for i, ext := range cr.Extensions {
			if len(ext.Value) != 0 {
				a.Logger.Info("\t%d: %s = %s\n", i, ext.Id.String(), strings.TrimSpace(string(ext.Value)))
			}
		}
	}
}

// HostnameMatch looks at the Autosign to see if the Hostname match matches one of the AutosignPatterns provided by the
// autosignConfig
func (a *autosign) HostnameMatch() bool {
	a.Logger.Info("Begining hostnamematch for %s\n", a.Hostname)
	for _, pattern := range a.Config.AutosignPatterns {
		a.Logger.Info("Checking pattern '%s'\n", pattern)
		if match, err := regexp.MatchString(pattern, a.Hostname); err != nil {
			a.Logger.Warn("Failed to compile pattern %s\n\t%s\n", pattern, err)
		} else {
			if match {
				a.Logger.Info("Matching pattern %s for CertName %s\n", pattern, a.Hostname)
				return true /* return on first match */
			}
		}
	}
	a.Logger.Info("Do not sign %s Failed to match any pattern\n", a.Hostname)
	return false
}

// HostnameMatch will compile and return if the hostname matches one of the patterns in the list
// will return the last error received if unable to compile the regexp
func HostnameMatch(ac *AutosignConfig, hostname string) (bool, error) {
	var err error
	for _, pattern := range ac.AutosignPatterns {
		if match, regexError := regexp.MatchString(pattern, hostname); regexError != nil {
			err = regexError
		} else {
			if match {
				return true, nil
			}
		}
	}
	return false, err
}

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
