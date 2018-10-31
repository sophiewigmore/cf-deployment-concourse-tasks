package checkexpiry

import (
	"code.cloudfoundry.org/credhub-cli/credhub/credentials"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

//go:generate counterfeiter . CredhubClient
type CredhubClient interface {
	FindByPartialName(nameLike string) (credentials.FindResults, error)
	GetLatestCertificate(name string) (credentials.Certificate, error)
}

func CheckExpiry(certs []credentials.Certificate, days time.Duration) (certNames []string) {
	for _, cert := range certs {
		pemString := cert.Value.Certificate
		if isExpiring, err := IsNearExpiry(pemString, days); err == nil && isExpiring {
			certNames = append(certNames, cert.Name)
		}
	}
	return certNames
}

func FetchCertificatesFromCredhub(credhubClient CredhubClient) (certs []credentials.Certificate, err error) {
	results, err := credhubClient.FindByPartialName("")
	if err != nil {
		return nil, err
	}
	for _, result := range results.Credentials {
		c, err := credhubClient.GetLatestCertificate(result.Name)
		if err == nil {
			certs = append(certs, c)
		}
	}
 	return certs, nil
}

func IsNearExpiry(pemString string, days time.Duration) (bool, error) {
	// Decode
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return false, errors.New("empty or invalid certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	currentTime := time.Now()
	expiryTime := cert.NotAfter.Add(-days)
	if currentTime.After(expiryTime) {
		return true, nil
	}
	return false, err
}
