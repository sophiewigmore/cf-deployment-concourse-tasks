package main

import (
	"code.cloudfoundry.org/credhub-cli/credhub"
	"code.cloudfoundry.org/credhub-cli/credhub/auth"
	"fmt"
	"github.com/cf-deployment-concourse-tasks/check-certificate-expiry/checkexpiry"
	"os"
	"time"
)

const thirtyDays = 24 * 30 * time.Hour

func main() {
	// create credhub client
	credhubAPI := os.Getenv("CREDHUB_SERVER")
	credhubCACert := os.Getenv("CREDHUB_CA_CERT")
	credhubClient := os.Getenv("CREDHUB_CLIENT")
	credhubSecret := os.Getenv("CREDHUB_SECRET")
	ch, err := credhub.New(
		credhubAPI,
		credhub.CaCerts(credhubCACert),
		credhub.SkipTLSValidation(false),
		credhub.Auth(auth.UaaClientCredentials(
			credhubClient,
			credhubSecret,
	)))

	if err != nil {
		fmt.Println(err)
	}

	certs, err := checkexpiry.FetchCertificatesFromCredhub(ch)
	if err != nil {
		fmt.Println(err)
	}

	expiringCerts := checkexpiry.CheckExpiry(certs, thirtyDays)

	for _, expiringCert := range expiringCerts {
		fmt.Printf("%s is expiring\n", expiringCert)
	}
}