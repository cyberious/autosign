package cert

import (
	"testing"

	"io/ioutil"
)

func TestNewPuppetCertificateRequest(t *testing.T) {
	expect := "ubuntu.mydomain.local"
	certBytes, err := ioutil.ReadFile("/Users/cyberious/gopath/src/github.com/cyberious/autosign/certs/ubuntu.mydomain.local.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes)
	if pcr == nil {
		t.Error("No valid puppet cert was return")
	}
	if pcr.Subject.CommonName != expect {
		t.Errorf("Expected common name was %s but got %s", expect, pcr.Subject.CommonName)
	}
}

func TestPasswordMatch(t *testing.T) {
	certBytes, err := ioutil.ReadFile("/Users/cyberious/gopath/src/github.com/cyberious/autosign/certs/ubuntu.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes)
	if pass, err := pcr.PasswordMatch("test"); err != nil {
		t.Errorf("An error has occured trying to match password %s\n", err)
	} else {
		if !pass {
			pwd, _ := pcr.challengePassword()
			t.Errorf("Expected to match password %s", pwd)
		}
	}
	pwd, _ := pcr.challengePassword()
	if pwd == "" {
		t.Error("Password is empty")
	}

}

func TestHasDNSNames_False(t *testing.T) {
	certBytes, err := ioutil.ReadFile("/Users/cyberious/gopath/src/github.com/cyberious/autosign/certs/ubuntu.mydomain.local.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes)
	if err != nil {
		t.Error("Error occured during parsing of certificate")
	}
	if pcr.HasDNSNames() {
		t.Error("Expected to have no DNS alt Names")
	}
}

func TestHasDNSNames_True(t *testing.T) {
	certBytes, err := ioutil.ReadFile("/Users/cyberious/gopath/src/github.com/cyberious/autosign/certs/ubuntu.alt.local.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes)
	if err != nil {
		t.Error("Error occured during parsing of certificate")
	}
	if !pcr.HasDNSNames() {
		t.Error("Expected to have no DNS alt Names")
	}
}
