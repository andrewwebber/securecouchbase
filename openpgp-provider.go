package securecouchbase

import (
	"golang.org/x/crypto/openpgp"
	"io"
)

// OpenPGPSecurityProvider is a OpenPGP implementation of the security provider interface
type OpenPGPSecurityProvider struct {
	privateKeyRing openpgp.EntityList
	publicKeyRing  openpgp.EntityList
}

// NewOpenPGPSecurityProvider creates a new OpenPGPSecurityProvider given a private and public key ring
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

// Decrypt decrypts the contents of a reader
func (p *OpenPGPSecurityProvider) Decrypt(reader io.Reader) (io.ReadCloser, error) {
	return Decrypt(reader, p.privateKeyRing)
}

// Encrypt encrypts the contents of a reader
func (p *OpenPGPSecurityProvider) Encrypt(reader io.Reader, writer io.Writer) error {
	return Encrypt(reader, writer, p.publicKeyRing)
}

// Sign signs the contents of a reader and writes the signature to the writer
func (p *OpenPGPSecurityProvider) Sign(reader io.Reader, writer io.Writer) error {
	return Sign(reader, writer, p.privateKeyRing)
}

// SignDetached signs the contents of a reader and writes the detached signature to the writer
func (p *OpenPGPSecurityProvider) SignDetached(reader io.Reader, writer io.Writer) error {
	return SignDetached(reader, writer, p.privateKeyRing)
}

// Verify validates a reader with signature within the contents of the reader
func (p *OpenPGPSecurityProvider) Verify(signed io.Reader) ([]byte, error) {
	return Verify(signed, p.publicKeyRing)
}

// VerifyDetached validates the contents of signed with a seperate signature
func (p *OpenPGPSecurityProvider) VerifyDetached(signed, signature io.Reader) error {
	return VerifyDetached(signed, signature, p.publicKeyRing)
}
