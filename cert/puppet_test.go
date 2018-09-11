package cert

import (
	"testing"

	"io/ioutil"
)

func TestNewPuppetCertificateRequest(t *testing.T) {
	expect := "ubuntu.mydomain.local"
	certBytes, err := ioutil.ReadFile("../certs/ubuntu.mydomain.local.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes, "ubuntu.mydomain.local")
	if pcr == nil {
		t.Error("No valid puppet cert was return")
	}
	if pcr.Subject.CommonName != expect {
		t.Errorf("Expected common name was %s but got %s", expect, pcr.Subject.CommonName)
	}
}

func TestPasswordMatch(t *testing.T) {
	expect := "test#5123k"
	certBytes, err := ioutil.ReadFile("../certs/ubuntu.mydomain.local_withattributes.pem")
	if err != nil {
		t.Errorf("Was unable to read cert for test:\n\t %s", err)
	}
	//p, _ := pem.Decode(certBytes)
	pcr, err := NewPuppetCertificateRequest(certBytes, "ubuntu.mydomain.local")
	if err != nil {
		t.Errorf("Was unable to read cert for test:\n\t %s", err)
	}
	pwd, err := pcr.challengePassword()
	if err != nil {
		t.Errorf("Unable to parse for challengePassword\n\t %s", err)
	}
	if pwd != expect {
		t.Errorf("Expected to match password %s\n", pwd)
	}
}

func TestGetOid(t *testing.T) {
	expect := "role::base"
	certBytes, err := ioutil.ReadFile("../certs/ubuntu.mydomain.local_withattributes.pem")
	if err != nil {
		t.Errorf("Was unable to read cert for test:\n\t %s", err)
	}

	pcr, _ := NewPuppetCertificateRequest(certBytes, "ubuntu.mydomain.local")
	oid := oidPuppetMap["pp_role"]
	got, err := pcr.GetAttributeByOid(oid)
	if err != nil {
		t.Errorf("An error was raised looking for %s\n\t%s", oid.String(), err)
	}
	if got != expect {
		t.Errorf("Expected to get %s but got %s", expect, got)
	}

}

func TestHasDNSNames_False(t *testing.T) {
	certBytes, err := ioutil.ReadFile("../certs/ubuntu.mydomain.local.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes, "ubuntu.mydomain.local")
	if err != nil {
		t.Error("Error occured during parsing of certificate")
	}
	if pcr.HasDNSNames() {
		t.Error("Expected to have no DNS alt Names")
	}
}

func TestHasDNSNames_True(t *testing.T) {
	certBytes, err := ioutil.ReadFile("../certs/ubuntu.alt.local.pem")
	if err != nil {
		t.Error("Was unable to read cert for test")
	}
	pcr, err := NewPuppetCertificateRequest(certBytes, "ubuntu.alt.local")
	if err != nil {
		t.Error("Error occured during parsing of certificate")
	}
	if !pcr.HasDNSNames() {
		t.Error("Expected to have no DNS alt Names")
	}
}
