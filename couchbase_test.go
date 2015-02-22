package securecouchbase_test

import (
	"testing"

	"github.com/andrewwebber/securecouchbase"
	"github.com/andrewwebber/walrus"
)

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

func TestVerifiableBucket(t *testing.T) {
	provider, err := NewSecurityProvider()
	if err != nil {
		t.Fatal(err)
	}

	bucket := walrus.NewBucket("bucketname")
	var testBucket securecouchbase.Bucket
	testBucket = bucket

	structure := TestStructure{"bar", NestedStructure{46}}
	err = securecouchbase.SetWithSignature("foo", 0, structure, testBucket, provider)
	if err != nil {
		t.Fatal(err)
	}

	var result TestStructure
	err = securecouchbase.GetWithSignature("foo", &result, testBucket, provider)
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
