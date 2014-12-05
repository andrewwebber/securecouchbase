package securecouchbase

import "io"

type SecurityProvider interface {
	Decrypt(reader io.Reader) (io.ReadCloser, error)
	Encrypt(reader io.Reader, writer io.Writer) error
	Sign(reader io.Reader, writer io.Writer) error
	SignDetached(reader io.Reader, writer io.Writer) error
	Verify(signed io.Reader) ([]byte, error)
	VerifyDetached(signed, signature io.Reader) error
}
