package securecouchbase

type Bucket interface {
	Get(k string, rv interface{}) error
	Set(k string, exp int, v interface{}) error
}
