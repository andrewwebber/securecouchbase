package securecouchbase_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/andrewwebber/securecouchbase"
	"github.com/couchbaselabs/go-couchbase"
)

type TestStructure struct {
	Message         string
	NestedStructure NestedStructure
}

type NestedStructure struct {
	Number int
}

var testBucket *couchbase.Bucket

func init() {
	bc, err := couchbase.Connect("http://localhost:8091")
	if err != nil {
		log.Fatal(fmt.Sprintf("Error connecting to couchbase : %v", err))
	}

	pool, err := bc.GetPool("default")
	if err != nil {
		log.Fatal(fmt.Sprintf("Error getting pool:  %v", err))
	}

	bucket, err := pool.GetBucket("cqrs")
	if err != nil {
		log.Fatal(fmt.Sprintf("Error getting bucket:  %v", err))
	}

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

	testBucket.Delete("adde")
	structure2 := TestStructure{"addTest", NestedStructure{46}}
	var success bool
	success, err = securecouchbase.AddWithEncryption("adde", 0, structure2, testBucket, provider)
	if err != nil {
		t.Fatal(err)
	}

	if !success {
		t.Fatal("not success")
	}

	success, err = securecouchbase.AddWithEncryption("adde", 0, structure2, testBucket, provider)
	if err != nil {
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

	var result TestStructure
	var cas uint64
	err = securecouchbase.GetsWithSignature("foo", &result, testBucket, provider, &cas)
	if err != nil {
		t.Fatal(err)
	}

	if result.Message != structure.Message {
		t.Fatal("Expected Message to be same")
	}

	err = securecouchbase.SetCasWithSignature("foo", 0, structure, testBucket, provider, cas)
	if err != nil {
		t.Fatal(err)
	}

	err = securecouchbase.SetCasWithSignature("foo", 0, structure, testBucket, provider, cas)
	if err == nil {
		t.Fatal("Expect CAS error")
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

	testBucket.Delete("adds")
	structure2 := TestStructure{"addTest", NestedStructure{46}}
	var success bool
	success, err = securecouchbase.AddWithSignature("adds", 0, structure2, testBucket, provider)
	if err != nil {
		t.Fatal(err)
	}

	if !success {
		t.Fatal("not success")
	}

	success, err = securecouchbase.AddWithSignature("adds", 0, structure2, testBucket, provider)
	if err != nil {
		t.Fatal(err)
	}

	if success {
		t.Fatal("not success 2 expected")
	}
}
