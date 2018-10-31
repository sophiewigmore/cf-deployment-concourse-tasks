package checkexpiry_test

import (
	"bytes"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials"
	"code.cloudfoundry.org/credhub-cli/credhub/credentials/values"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/cf-deployment-concourse-tasks/check-certificate-expiry/checkexpiry"
	"github.com/cf-deployment-concourse-tasks/check-certificate-expiry/checkexpiry/checkexpiryfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"log"
	"math/big"
	"time"
)

const twentyNineDays = 29 * 24 * time.Hour
const thirtyDays = 30 * 24 * time.Hour
const thirtyOneDays = 31 * 24 * time.Hour


func dynamicallyGenerateCertificate(days time.Duration) (string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Pivotal CF"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(days),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Panicf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return out.String()
}

var _ = Describe("CheckExpiry", func() {

	Describe("#CheckExpiry", func() {
		Context("Check cert list for expired certs", func() {
			It("Will return only certs near expiry", func() {
				certList := []credentials.Certificate{
					{
						Metadata: credentials.Metadata{Base: credentials.Base{Name: "foo"}},
						Value: values.Certificate{Certificate: dynamicallyGenerateCertificate(twentyNineDays)},
					},
					{
						Metadata: credentials.Metadata{Base: credentials.Base{Name: "bar"}},
						Value: values.Certificate{Certificate: dynamicallyGenerateCertificate(thirtyDays)},
					},
					{
						Metadata: credentials.Metadata{Base: credentials.Base{Name: "baz"}},
						Value: values.Certificate{Certificate: dynamicallyGenerateCertificate(thirtyOneDays)},
					},
				}
				Expect(checkexpiry.CheckExpiry(certList, thirtyDays)).To(ConsistOf("foo", "bar"))
			})
		})
	})

	Describe("#FetchCertificatesFromCredhub", func() {
		Context("We correctly grab expected certificates", func() {
			It("The function will grab the fake credhub certs", func() {
				credhubClient := new(checkexpiryfakes.FakeCredhubClient)
				credentialsInCredhub := credentials.FindResults{
					Credentials: []credentials.Base{
						{Name: "foo"},
						{Name: "bar"},
					},
				}

				fooCert := credentials.Certificate{Metadata: credentials.Metadata{Base: credentials.Base{Name: "foo"}}}
				credhubClient.FindByPartialNameReturns(credentialsInCredhub, nil)
				credhubClient.GetLatestCertificateReturnsOnCall(0, fooCert, nil)
				credhubClient.GetLatestCertificateReturnsOnCall(1, credentials.Certificate{}, errors.New("not a certificate"))

				certs, err := checkexpiry.FetchCertificatesFromCredhub(credhubClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(certs)).To(Equal(1))
				Expect(certs[0].Name).To(Equal("foo"))
			})
		})
	})

	Describe("#IsNearExpiry", func() {
		Context("Basic error case handling for invalid or missing certificates", func() {
			It("empty string should error", func() {
				certificate := ``
				_, err := checkexpiry.IsNearExpiry(certificate, thirtyDays)
				Expect(err).To(HaveOccurred())
			})

			It("non-cert string should error", func() {
				certificate := `Hello foobar`
				_, err := checkexpiry.IsNearExpiry(certificate, thirtyDays)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when a certificate expires in more than 30 days in the future", func() {
			It("returns false", func() {
				certificate := dynamicallyGenerateCertificate(thirtyOneDays)
				Expect(checkexpiry.IsNearExpiry(certificate, thirtyDays)).To(BeFalse())
			})
		})

		Context("when a certificate is near expiry, e.g. under 30 days", func() {
			It("returns true", func() {
				certificate := dynamicallyGenerateCertificate(twentyNineDays)
				Expect(checkexpiry.IsNearExpiry(certificate, thirtyDays)).To(BeTrue())
			})
		})
	})
})
