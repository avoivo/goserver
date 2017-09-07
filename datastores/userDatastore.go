package datastores

import (
	"github.com/avoivo/goserver/models"
	gocb "gopkg.in/couchbase/gocb.v1"
)

// UserDataStore describes user's model data interaction
type UserDataStore interface {
	Create(u models.User) error
	Read(id string) (user models.User, err error)
	Update(u models.User) error
	Delete(id string) error
}

// CouchBaseUserDataStore handles data interaction with a couchbase server
type CouchBaseUserDataStore struct {
	bucket *gocb.Bucket
}

// Create a user
func (d *CouchBaseUserDataStore) Create(u models.User) error {
	if _, err := d.bucket.Insert(u.ID, u, 0); err != nil {
		return err
	}
	return nil

}

// Read a user
func (d *CouchBaseUserDataStore) Read(id string) (user models.User, err error) {
	_, err = d.bucket.Get(id, &user)
	return
}

// Update a user
func (d *CouchBaseUserDataStore) Update(u models.User) error {

	if _, err := d.bucket.Replace(u.ID, u, 0, 0); err != nil {
		return err
	}

	return nil
}

// Delete a user
func (d *CouchBaseUserDataStore) Delete(id string) error {
	if _, err := d.bucket.Remove(id, 0); err != nil {
		return err
	}
	return nil
}
