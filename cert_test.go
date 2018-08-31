package main

import (
	"crypto/x509"
	"testing"
)

func TesthasDNSNames(t *testing.T) {
	cr := x509.CertificateRequest{DNSNames: []string{"test", "me"}}
	if !hasDNSNames(cr) {
		t.Error("Expected to have DNSnames")
	}
}
