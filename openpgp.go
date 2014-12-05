package securecouchbase

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
)

// ArmorEncoder encodes to a text friendly format
func ArmorEncoder(writer io.Writer) (io.WriteCloser, error) {
	header := make(map[string]string)
	header["Content-Type"] = "text/plain;charset=us-ascii"
	return armor.Encode(writer, openpgp.SignatureType, header)
}

// ArmorDecode decodes a preivously encoded armor encoded stream
func ArmorDecode(reader io.Reader) (io.Reader, error) {
	block, err := armor.Decode(reader)
	if err != nil {
		return nil, err
	}

	return block.Body, nil
}

// Decrypt decrypts data that has been encrypted and compressed
func Decrypt(reader io.Reader, secertKeyring openpgp.EntityList) (io.ReadCloser, error) {
	md, err := openpgp.ReadMessage(reader, secertKeyring, nil, nil)
	if err != nil {
		return nil, err
	}

	return gzip.NewReader(md.UnverifiedBody)
}

// Encrypt compresses data and then encrypts it
// data is encrypted with all public keys found in the supplied keyring.
func Encrypt(reader io.Reader, writer io.Writer, publicKeyRing openpgp.EntityList) error {
	pgpWriter, err := openpgp.Encrypt(writer, publicKeyRing, nil, nil, nil)
	if err != nil {
		return err
	}

	gzWriter := gzip.NewWriter(pgpWriter)
	io.Copy(gzWriter, reader)
	if err := gzWriter.Close(); err != nil {
		return err
	}

	if err := pgpWriter.Close(); err != nil {
		return err
	}

	return nil
}

// Sign signs data and creates a clear sign armor encoded message
func Sign(reader io.Reader, writer io.Writer, privateKeyring openpgp.EntityList) error {
	plaintext, err := clearsign.Encode(writer, privateKeyring[0].PrivateKey, nil)
	if err != nil {
		return err
	}

	_, err = io.Copy(plaintext, reader)
	if err != nil {
		return err
	}

	plaintext.Close()

	return nil
}

// SignDetached signs data and writes the raw signature to the writer
func SignDetached(reader io.Reader, writer io.Writer, privateKeyring openpgp.EntityList) error {
	return openpgp.DetachSign(writer, privateKeyring[0], reader, nil)
}

// Verify reads a clear signed message returning the body of the messages after verification has been successful
func Verify(signed io.Reader, publicKeyRing openpgp.EntityList) ([]byte, error) {
	signedBuffer, err := ioutil.ReadAll(signed)
	if err != nil {
		return nil, err
	}

	block, _ := clearsign.Decode(signedBuffer)

	if _, err := openpgp.CheckDetachedSignature(publicKeyRing, bytes.NewBuffer(block.Bytes), block.ArmoredSignature.Body); err != nil {
		return nil, errors.New("failed to check signature: " + err.Error())
	}

	return block.Bytes, nil
}

// VerifyDetached verifies a seperate signature against a source
func VerifyDetached(signed, signature io.Reader, publicKeyRing openpgp.EntityList) error {
	if _, err := openpgp.CheckDetachedSignature(publicKeyRing, signed, signature); err != nil {
		return errors.New("failed to check signature: " + err.Error())
	}

	return nil
}
