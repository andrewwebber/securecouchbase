package securecouchbase_test

import (
	"testing"

	"github.com/andrewwebber/securecouchbase"

	"gopkg.in/couchbase/gocb.v1"
)

type TestStructure struct {
	Message         string
	NestedStructure NestedStructure
}

type NestedStructure struct {
	Number int
}

var testBucket *gocb.Bucket

func init() {
	cluster, _ := gocb.Connect("couchbase://localhost")
	cluster.Authenticate(gocb.PasswordAuthenticator{
		Username: "Administrator",
		Password: "password",
	})
	bucket, _ := cluster.OpenBucket("default", "")

	testBucket = bucket
}

func TestEncryptionBucket(t *testing.T) {
	provider, err := NewSecurityProvider()
	if err != nil {
		t.Fatal(err)
	}

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

	testBucket.Remove("adde", 0)
	structure2 := TestStructure{"addTest", NestedStructure{46}}
	var success bool
	success, err = securecouchbase.AddWithEncryption("adde", 0, structure2, testBucket, provider)
	if err == nil {
		t.Fatal(err)
	}

	if success {
		t.Fatal("not success")
	}

	success, err = securecouchbase.AddWithEncryption("adde", 0, structure2, testBucket, provider)
	if err == nil {
		t.Fatal(err)
	}

	if success {
		t.Fatal("not success 2 expected")
	}
}

func TestCas(t *testing.T) {
	provider, err := NewSecurityProvider()
	if err != nil {
		t.Fatal(err)
	}

	structure := TestStructure{"bar", NestedStructure{46}}
	err = securecouchbase.SetWithSignature("foo", 0, structure, testBucket, provider)
	if err != nil {
		t.Fatal(err)
	}

}

func TestVerifiableBucket(t *testing.T) {
	provider, err := NewSecurityProvider()
	if err != nil {
		t.Fatal(err)
	}

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

	testBucket.Remove("adds", 0)
	structure2 := TestStructure{"addTest", NestedStructure{46}}
	var success bool
	success, err = securecouchbase.AddWithSignature("adds", 0, structure2, testBucket, provider)
	if err == nil {
		t.Fatal(err)
	}

	if success {
		t.Fatal("not success")
	}

	success, err = securecouchbase.AddWithSignature("adds", 0, structure2, testBucket, provider)
	if err == nil {
		t.Fatal(err)
	}

	if success {
		t.Fatal("not success 2 expected")
	}
}
