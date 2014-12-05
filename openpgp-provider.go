package securecouchbase

import (
	"golang.org/x/crypto/openpgp"
	"io"
)

type OpenPGPSecurityProvider struct {
	privateKeyRing openpgp.EntityList
	publicKeyRing  openpgp.EntityList
}

func NewOpenPGPSecurityProvider(privateKeyRingReader, publicKeyRingReader io.Reader) (*OpenPGPSecurityProvider, error) {
	privateKeyRing, err := openpgp.ReadArmoredKeyRing(privateKeyRingReader)
	if err != nil {
		return nil, err
	}

	publicKeyRing, err := openpgp.ReadArmoredKeyRing(publicKeyRingReader)
	if err != nil {
		return nil, err
	}

	return &OpenPGPSecurityProvider{privateKeyRing, publicKeyRing}, nil
}

func (p *OpenPGPSecurityProvider) Decrypt(reader io.Reader) (io.ReadCloser, error) {
	return Decrypt(reader, p.privateKeyRing)
}

func (p *OpenPGPSecurityProvider) Encrypt(reader io.Reader, writer io.Writer) error {
	return Encrypt(reader, writer, p.publicKeyRing)
}

func (p *OpenPGPSecurityProvider) Sign(reader io.Reader, writer io.Writer) error {
	return Sign(reader, writer, p.privateKeyRing)
}

func (p *OpenPGPSecurityProvider) SignDetached(reader io.Reader, writer io.Writer) error {
	return SignDetached(reader, writer, p.privateKeyRing)
}

func (p *OpenPGPSecurityProvider) Verify(signed io.Reader) ([]byte, error) {
	return Verify(signed, p.publicKeyRing)
}

func (p *OpenPGPSecurityProvider) VerifyDetached(signed, signature io.Reader) error {
	return VerifyDetached(signed, signature, p.publicKeyRing)
}
