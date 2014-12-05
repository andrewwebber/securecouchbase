securecouchbase [![Build Status](https://drone.io/github.com/andrewwebber/securecouchbase/status.png)](https://drone.io/github.com/andrewwebber/securecouchbase/latest)
===============

## Secure Couchbase Project Requirments

- In some cases it is not acceptable to allow a couchbase administrator to edit JSON entries
- In some cases it is not acceptable to allow a couchbase read-only administrator to read confidential entries

Secure couchbase uses OpenPGP to wrap bucket calls with encrypted or sign variants of Set and Get operations

## Getting started

### Create a GPG key ring
```sh
$gpg2 --batch --gen-key --armor gpg.batch
```

### Create your own security provider - or use the OpenPGP default
```golang
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
```


### Start writing to a bucket
```golang
type TestStructure struct {
  Message         string
  NestedStructure NestedStructure
}

type NestedStructure struct {
  Number int
}

func TestEncryptionBucket(t *testing.T) {
  provider, err := NewSecurityProvider()
  if err != nil {
    t.Fatal(err)
  }

  bucket := walrus.NewBucket("bucketname")
  var testBucket securecouchbase.Bucket
  testBucket = bucket

  structure := TestStructure{"bar", NestedStructure{46}}
  err = securecouchbase.SetWithEncryption("foo", 0, structure, testBucket, provider)
  if err != nil {
    t.Fatal(err)
  }

  var result TestStructure
  err = securecouchbase.GetWithEncryption("foo", &result, testBucket, provider)
  if err != nil {
    t.Fatal(err)
  }

  if result.Message != structure.Message {
    t.Fatal("Expected Message to be same")
  }

  if result.NestedStructure.Number != structure.NestedStructure.Number {
    t.Fatal("Expected nested structure number to be equal")
  }
}
```
