package datastores

import (
	"fmt"
	"log"
	"strings"

	gocb "gopkg.in/couchbase/gocb.v1"
)

// UserDataStoreFactory does something interesting
type UserDataStoreFactory func(conf map[string]string) (UserDataStore, error)

// NewCouchBaseUserDataStore does something interesting
func NewCouchBaseUserDataStore(conf map[string]string) (UserDataStore, error) {
	connectionString, ok := conf["CONNECTION_STRING"]
	if !ok {
		return nil, fmt.Errorf("%s is required for the couchbase datastore", "CONNECTION_STRING")
	}

	bucketName, ok := conf["BUCKET_NAME"]
	if !ok {
		return nil, fmt.Errorf("%s is required for the couchbase datastore", "BUCKET_NAME")
	}

	password, ok := conf["PASSWORD"]

	cluster, err := gocb.Connect(connectionString)
	if err != nil {
		return nil, err
	}

	bucket, err := cluster.OpenBucket(bucketName, password)
	if err != nil {
		return nil, err
	}

	return &CouchBaseUserDataStore{bucket: bucket}, nil

}

var userDatastoreFactories = make(map[string]UserDataStoreFactory)

// RegisterUserDatastore does something interesting
func RegisterUserDatastore(name string, factory UserDataStoreFactory) {
	if factory == nil {
		log.Panicf("Datastore factory %s does not exist.", name)
	}
	_, registered := userDatastoreFactories[name]
	if registered {
		log.Panicf("Datastore factory %s already registered. Ignoring.", name)

	}
	userDatastoreFactories[name] = factory
}

// CreateUserDatastore does something great
func CreateUserDatastore(conf map[string]string) (UserDataStore, error) {

	// Query configuration for datastore defaulting to "couchbase".
	engineName, ok := conf["DATASTORE"]
	if !ok {
		engineName = "couchbase"
	}

	engineFactory, ok := userDatastoreFactories[engineName]
	if !ok {
		// Factory has not been registered.
		// Make a list of all available datastore factories for logging.
		availableDatastores := make([]string, len(userDatastoreFactories))
		for k := range userDatastoreFactories {
			availableDatastores = append(availableDatastores, k)
		}
		return nil, fmt.Errorf("Invalid Datastore name. Must be one of: %s", strings.Join(availableDatastores, ", "))
	}

	// Run the factory with the configuration.
	return engineFactory(conf)
}

func init() {
	RegisterUserDatastore("couchbase", NewCouchBaseUserDataStore)
}
