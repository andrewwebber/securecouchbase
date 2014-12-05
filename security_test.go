package securecouchbase_test

import (
	"bytes"
	"github.com/andrewwebber/securecouchbase"
	"io"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var (
	key           = "/brainloop/util/security/test"
	publicKeyring = "pubring.gpg"
	secretKeyring = "secring.gpg"
)

func NewSecurityProvider() (securecouchbase.SecurityProvider, error) {
	privateKeyRingReader, err := os.Open(secretKeyring)
	if err != nil {
		return nil, err
	}

	publicKeyRingReader, err := os.Open(publicKeyring)
	if err != nil {
		return nil, err
	}

	return securecouchbase.NewOpenPGPSecurityProvider(privateKeyRingReader, publicKeyRingReader)
}

func TestEncodeDecode(t *testing.T) {
	provider, err := NewSecurityProvider()
	if err != nil {
		t.Fatal(err)
	}

	originalMessage := "TestEncodeDecode - original message"

	buffer := new(bytes.Buffer)
	armorEncoder, err := securecouchbase.ArmorEncoder(buffer)
	err = provider.Encrypt(bytes.NewBufferString(originalMessage), armorEncoder)
	if err != nil {
		t.Error(err)
	}

	armorEncoder.Close()
	encodedBytes := buffer.Bytes()
	t.Log(string(encodedBytes))
	ioutil.WriteFile("TestEncodeDecode.testoutput", buffer.Bytes(), 0644)

	decoder, err := securecouchbase.ArmorDecode(bytes.NewBuffer(encodedBytes))
	decryptedReader, err := provider.Decrypt(decoder)
	if err != nil {
		t.Error(err)
	}

	decoded := new(bytes.Buffer)
	io.Copy(decoded, decryptedReader)

	decodedMesage := string(decoded.Bytes())
	t.Log(decodedMesage)
	if decodedMesage != originalMessage {
		log.Fatalln("original and decoded messages do not match")
	}
}

func TestSign(t *testing.T) {
	provider, err := NewSecurityProvider()
	if err != nil {
		t.Fatal(err)
	}

	originalBuffer := bytes.NewBufferString("hello world")
	buffer := new(bytes.Buffer)
	err = provider.Sign(originalBuffer, buffer)
	if err != nil {
		log.Fatalln(err)
	}

	encodedBytes := buffer.Bytes()
	t.Log(string(encodedBytes))

	content, err := provider.Verify(bytes.NewReader(encodedBytes))
	if err != nil {
		log.Fatalln(err)
	}

	t.Log("signed content : " + string(content))
}
