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

type PuppetCertificateRequest struct {
	PemBlock *pem.Block
	*x509.CertificateRequest
}

func (pcr *PuppetCertificateRequest) HasDNSNames() bool {
	if pcr.CertificateRequest == nil {
		return false
	}

	fmt.Println("Attempting to parse for DNS Names")
	return len(pcr.CertificateRequest.DNSNames) > 0
}

// Check to see if the password is a match without exposing the actual password
// Returns false and nil if no password exists in the file
func (pcr *PuppetCertificateRequest) PasswordMatch(pass string) (bool, error) {
	if csrPass, err := pcr.GetAttributeByOid(oidPuppetMap["challengePassword"]); err != nil {
		return false, err
	} else {
		return csrPass == pass, nil
	}
	return false, nil
}

func (pcr *PuppetCertificateRequest) HasPassword() bool {
	pass, _ := pcr.challengePassword()
	return pass != ""
}

func NewPuppetCertificateRequest(bytes []byte) (*PuppetCertificateRequest, error) {
	fmt.Println("Attemping to decode certificate request")
	pemBlock, _ := pem.Decode(bytes)
	cr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		fmt.Printf("An error has occured %s", err)
		return nil, err
	}

	if err != nil {
		fmt.Errorf("An error has occured parsing for password %s", err)
		return nil, err
	}
	if cr == nil {
		return nil, errors.New("Failed to get valid certificate")
	}
	return &PuppetCertificateRequest{PemBlock: pemBlock, CertificateRequest: cr}, nil
}

func (pcr *PuppetCertificateRequest) Bytes() []byte {
	return pcr.PemBlock.Bytes
}

func (pcr *PuppetCertificateRequest) challengePassword() (string, error) {
	for _, ext := range pcr.Extensions {
		if ext.Id.Equal(oidPuppetMap["challengePassword"]) {
			return strings.TrimSpace(string(ext.Value)), nil
		}
	}
	return "", errors.New("No password found")
}

func (pcr *PuppetCertificateRequest) GetAttributeByOid(oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range pcr.Extensions {
		if ext.Id.Equal(oid) {
			if len(ext.Value) > 0 {
				return strings.TrimSpace(string(ext.Value)), nil
			}
			return "", nil
		}
	}
	return "", nil
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

func PuppetExtensions() []pkix.Extension {
	exts := []pkix.Extension{}
	for k := range oidPuppetMap {
		exts = append(exts, pkix.Extension{Id: oidPuppetMap[k]})
	}
	return exts
}
