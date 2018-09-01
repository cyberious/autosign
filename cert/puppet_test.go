package cert

import (
	"testing"

	"io/ioutil"
)

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
