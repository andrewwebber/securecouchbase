package securecouchbase

import "io"

// SecurityProvider is an interface around encryption and verification implementations
type SecurityProvider interface {
	Decrypt(reader io.Reader) (io.ReadCloser, error)
	Encrypt(reader io.Reader, writer io.Writer) error
	Sign(reader io.Reader, writer io.Writer) error
	SignDetached(reader io.Reader, writer io.Writer) error
	Verify(signed io.Reader) ([]byte, error)
	VerifyDetached(signed, signature io.Reader) error
}
