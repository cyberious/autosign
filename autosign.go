package main

import (
	"fmt"
	"github.com/cyberious/autosign/cert"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type Autosign struct {
	Hostname           string
	Config             AutosignConfig
	CertificateRequest *cert.PuppetCertificateRequest
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
	pcr := a.CertificateRequest
	if !pcr.HasDNSNames() {
		a.Logger.Info("No DNS Alt Names\n")
		if len(a.Config.AutosignPatterns) == 0 {
			a.Logger.Info("Signing cert for %s: Reason, NO DNS Alt Names matches no pattern match set \n", a.Hostname)
			return true, nil
		} else {
			return a.HostnameMatch(), nil
		}
	}
	return false, nil
}

func (a *Autosign) LogCertDetails() {
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

func (a *Autosign) HostnameMatch() bool {
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

func HostnameMatch(ac AutosignConfig, hostname string) {

}

func (a *Autosign) CheckDNSAltNamesIfAny() bool {
	return false
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
