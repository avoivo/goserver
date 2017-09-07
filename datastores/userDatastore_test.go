package datastores

import (
	"testing"
	"time"

	"github.com/avoivo/goserver/models"
	gocb "gopkg.in/couchbase/gocb.v1"
)

const (
	couchBaseConnectionString = "couchbase://192.168.99.100"
	couchBaseBucketName       = "test"
	couchBaseBucketPassword   = "1233"
	couchBaseManagerName      = "Administrator"
	couchBaseManagerPassword  = "admin1"
)

func Test_CouchBaseUserDatastore_should_create(t *testing.T) {
	if err := couchBaseUserDatastore.Create(models.User{
		ID:       "1",
		Email:    "test@test.test",
		Name:     "test user",
		IsAdmin:  false,
		IsActive: true,
	}); err != nil {
		t.Error(err)
	}

	var u models.User
	if _, err := couchBaseUserDatastore.bucket.Get("1", &u); err != nil {
		t.Error(err)
	}

	if u.ID != "1" ||
		u.Email != "test@test.test" || u.Name != "test user" || u.IsAdmin || !u.IsActive {
		t.Error("user have invalid property values", u)
	}

}

func Test_CouchBaseUserDatastore_should_read(t *testing.T) {

	if err := couchBaseUserDatastore.Create(models.User{
		ID:       "2",
		Email:    "test@test.test",
		Name:     "test user",
		IsAdmin:  false,
		IsActive: true,
	}); err != nil {
		t.Error(err)
	}

	u, err := couchBaseUserDatastore.Read("2")
	if err != nil {
		t.Error(err)
	}

	if u.ID != "2" ||
		u.Email != "test@test.test" || u.Name != "test user" || u.IsAdmin || !u.IsActive {
		t.Error("user have invalid property values", u)
	}
}

func Test_CouchBaseUserDatastore_should_update(t *testing.T) {

	if err := couchBaseUserDatastore.Create(models.User{
		ID:       "3",
		Email:    "test@test.test",
		Name:     "test user",
		IsAdmin:  false,
		IsActive: true,
	}); err != nil {
		t.Error(err)
	}

	if err := couchBaseUserDatastore.Update(models.User{
		ID:       "3",
		Email:    "test2@test.test",
		Name:     "test user 2",
		IsAdmin:  true,
		IsActive: false,
	}); err != nil {
		t.Error(err)
	}

	u, err := couchBaseUserDatastore.Read("3")
	if err != nil {
		t.Error(err)
	}

	if u.ID != "3" ||
		u.Email != "test2@test.test" || u.Name != "test user 2" || !u.IsAdmin || u.IsActive {
		t.Error("user have invalid property values", u)
	}
}

func Test_CouchBaseUserDatastore_should_delete(t *testing.T) {

	if err := couchBaseUserDatastore.Create(models.User{
		ID:       "4",
		Email:    "test@test.test",
		Name:     "test user",
		IsAdmin:  false,
		IsActive: true,
	}); err != nil {
		t.Error(err)
	}

	if err := couchBaseUserDatastore.Delete("4"); err != nil {
		t.Error(err)
	}

	_, err := couchBaseUserDatastore.Read("4")
	if err == nil {
		t.Error("user was not deleted")
	}

}

var couchBaseUserDatastore CouchBaseUserDataStore

func init() {
	cluster, err := gocb.Connect(couchBaseConnectionString)
	if err != nil {
		panic(err)
	}

	manager := cluster.Manager(couchBaseManagerName, couchBaseManagerPassword)

	buckets, err := manager.GetBuckets()
	if err != nil {
		panic(err)
	}

	bucketExists := false
	for _, v := range buckets {

		if v.Name == couchBaseBucketName {
			bucketExists = true
			break
		}
	}

	if bucketExists {

		if err := manager.RemoveBucket(couchBaseBucketName); err != nil {
			panic(err)
		}
	}

	bucketSettings := gocb.BucketSettings{
		Name:     couchBaseBucketName,
		Password: couchBaseBucketPassword,
		Type:     gocb.Couchbase,
		Quota:    100,
	}

	if err := manager.InsertBucket(&bucketSettings); err != nil {
		panic(err.Error())
	}

	// give time for to the new bucket to be initialized
	time.Sleep(time.Second * 5)

	bucket, err := cluster.OpenBucket(couchBaseBucketName, couchBaseBucketPassword)
	if err != nil {
		panic(err)
	}

	couchBaseUserDatastore = CouchBaseUserDataStore{bucket: bucket}

}
