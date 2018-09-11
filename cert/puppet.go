package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"strings"
)

// PuppetCertificateRequest is a representation of the PuppetCertificateSigningRequest which will
// hold the Hostname as well as the x509.CertificateRequest and the PemBlock in order to see the raw un-parsed data.
type PuppetCertificateRequest struct {
	Hostname string
	PemBlock *pem.Block
	*x509.CertificateRequest
}

// HasDNSNames returns false if no request is present or the certificate DNSNames is empty
func (pcr *PuppetCertificateRequest) HasDNSNames() bool {
	if pcr.CertificateRequest == nil {
		return false
	}

	return len(pcr.CertificateRequest.DNSNames) > 0
}

// PasswordMatch check to see if the password is a match without exposing the actual password
// Returns false and nil if no password exists in the file
func (pcr *PuppetCertificateRequest) PasswordMatch(pass string) (bool, error) {
	csrPass, err := pcr.GetAttributeByOid(oidPuppetMap["challengePassword"])
	if err != nil {
		return false, err
	}

	return csrPass == pass, nil
}

// HasPassword attempts to get the password attribute and if not present or an empty string it will return false
func (pcr *PuppetCertificateRequest) HasPassword() bool {
	pass, _ := pcr.challengePassword()
	return pass != ""
}

// NewPuppetCertificateRequest returns a new PuppetCertificateRequest and requires certificate bytes and the hostname
func NewPuppetCertificateRequest(bytes []byte, hostname string) (*PuppetCertificateRequest, error) {
	fmt.Println("Attempting to decode certificate request")
	pemBlock, _ := pem.Decode(bytes)
	cr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		newError := fmt.Errorf("an error has occured parsing the certificate %s", err)
		return nil, newError
	}
	if cr == nil {
		return nil, errors.New("Failed to get valid certificate")
	}
	return &PuppetCertificateRequest{PemBlock: pemBlock, CertificateRequest: cr}, nil
}

// Bytes is a simple wrapper to simplify the Pemblock.Bytes call
func (pcr *PuppetCertificateRequest) Bytes() []byte {
	return pcr.PemBlock.Bytes
}

func (pcr *PuppetCertificateRequest) challengePassword() (string, error) {
	pwd, _ := pcr.GetAttributeByOid(oidPuppetMap["challengePassword"])
	if pwd == "" {
		return "", errors.New("No password found")

	}
	return pwd, nil
}

// GetAttributeByOid retrieves the string value from the certificate if it exists
func (pcr *PuppetCertificateRequest) GetAttributeByOid(oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range pcr.Extensions {
		if ext.Id.Equal(oid) {
			if len(ext.Value) > 0 {
				return strings.TrimSpace(string(ext.Value)), nil
			}
			return "", errors.New("Oid found but no value set")
		}
	}
	return "", errors.New("No object found")
}

var oidPuppetMap = map[string]asn1.ObjectIdentifier{
	"pp_uuid":             {1, 3, 6, 1, 4, 1, 34380, 1, 1, 1},
	"pp_instance_id":      {1, 3, 6, 1, 4, 1, 34380, 1, 1, 2},
	"pp_image_name":       {1, 3, 6, 1, 4, 1, 34380, 1, 1, 3},
	"pp_preshared_key":    {1, 3, 6, 1, 4, 1, 34380, 1, 1, 4},
	"pp_cost_center":      {1, 3, 6, 1, 4, 1, 34380, 1, 1, 5},
	"pp_product":          {1, 3, 6, 1, 4, 1, 34380, 1, 1, 6},
	"pp_project":          {1, 3, 6, 1, 4, 1, 34380, 1, 1, 7},
	"pp_application":      {1, 3, 6, 1, 4, 1, 34380, 1, 1, 8},
	"pp_service":          {1, 3, 6, 1, 4, 1, 34380, 1, 1, 9},
	"pp_employee":         {1, 3, 6, 1, 4, 1, 34380, 1, 1, 10},
	"pp_created_by":       {1, 3, 6, 1, 4, 1, 34380, 1, 1, 11},
	"pp_environment":      {1, 3, 6, 1, 4, 1, 34380, 1, 1, 12},
	"pp_role":             {1, 3, 6, 1, 4, 1, 34380, 1, 1, 13},
	"pp_software_version": {1, 3, 6, 1, 4, 1, 34380, 1, 1, 14},
	"pp_department":       {1, 3, 6, 1, 4, 1, 34380, 1, 1, 15},
	"pp_cluster":          {1, 3, 6, 1, 4, 1, 34380, 1, 1, 16},
	"pp_provisioner":      {1, 3, 6, 1, 4, 1, 34380, 1, 1, 17},
	"pp_region":           {1, 3, 6, 1, 4, 1, 34380, 1, 1, 18},
	"pp_datacenter":       {1, 3, 6, 1, 4, 1, 34380, 1, 1, 19},
	"pp_zone":             {1, 3, 6, 1, 4, 1, 34380, 1, 1, 20},
	"pp_network":          {1, 3, 6, 1, 4, 1, 34380, 1, 1, 21},
	"pp_securitypolicy":   {1, 3, 6, 1, 4, 1, 34380, 1, 1, 22},
	"pp_cloudplatform":    {1, 3, 6, 1, 4, 1, 34380, 1, 1, 23},
	"pp_apptier":          {1, 3, 6, 1, 4, 1, 34380, 1, 1, 24},
	"pp_hostname":         {1, 3, 6, 1, 4, 1, 34380, 1, 1, 25},
	"challengePassword":   {1, 2, 840, 113549, 1, 9, 7},
}

// PuppetExtensionsMap is the string to oid mappings used by puppet
func PuppetExtensionsMap() map[string]asn1.ObjectIdentifier {
	return oidPuppetMap
}

// PuppetExtensions is an array of extensions supported by puppet by default i.e. pp_role, pp_datacenter
func PuppetExtensions() []pkix.Extension {
	exts := []pkix.Extension{}
	for k := range oidPuppetMap {
		exts = append(exts, pkix.Extension{Id: oidPuppetMap[k]})
	}
	return exts
}
