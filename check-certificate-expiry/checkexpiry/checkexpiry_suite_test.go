package checkexpiry_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCheckexpiry(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Checkexpiry Suite")
}
