package securecouchbase

import (
	"bytes"
	"encoding/json"
	"io"
)

type EncryptedData struct {
	EncryptedAndSigned []byte
}

type ProtectedDataSet struct {
	Data      interface{}
	Signature []byte
}

type ProtectedDataRead struct {
	Data      json.RawMessage
	Signature []byte
}

func SetWithEncryption(id string, exp int, object interface{}, connection Bucket, provider SecurityProvider) error {
	enc, err := json.Marshal(object)
	if err != nil {
		return err
	}

	encryptedBuffer := new(bytes.Buffer)
	err = provider.Encrypt(bytes.NewReader(enc), encryptedBuffer)
	if err != nil {
		return err
	}

	encryptedData := EncryptedData{encryptedBuffer.Bytes()}
	if err := connection.Set(id, exp, encryptedData); err != nil {
		return err
	}

	return nil
}

func GetWithEncryption(id string, object interface{}, connection Bucket, provider SecurityProvider) error {
	var encryptedData EncryptedData
	err := connection.Get(id, &encryptedData)
	if err != nil {
		return err
	}

	decryptReader, err := provider.Decrypt(bytes.NewReader(encryptedData.EncryptedAndSigned))
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)
	io.Copy(buffer, decryptReader)
	decryptReader.Close()
	json.Unmarshal(buffer.Bytes(), object)

	return nil
}

func SetWithSignature(id string, exp int, object interface{}, connection Bucket, provider SecurityProvider) error {
	enc, err := json.Marshal(object)
	if err != nil {
		return err
	}

	sigBuffer := new(bytes.Buffer)
	err = provider.SignDetached(bytes.NewReader(enc), sigBuffer)
	if err != nil {
		return err
	}

	protectedData := ProtectedDataSet{object, sigBuffer.Bytes()}
	if err := connection.Set(id, exp, protectedData); err != nil {
		return err
	}

	return nil
}

func GetWithSignature(id string, object interface{}, connection Bucket, provider SecurityProvider) error {
	var protectedData ProtectedDataRead
	err := connection.Get(id, &protectedData)
	if err != nil {
		return err
	}

	err = provider.VerifyDetached(bytes.NewReader(protectedData.Data), bytes.NewReader(protectedData.Signature))
	if err != nil {
		return err
	}

	json.Unmarshal(protectedData.Data, object)

	return nil
}
