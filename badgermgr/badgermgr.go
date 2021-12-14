package badgermgr

import (
	"encoding/json"
	"fmt"
	"log"

	badger "github.com/dgraph-io/badger/v3"
)

var dbpath string
var db *badger.DB
var err error

type CertRecord struct {
	PubKey string
	Token  string
	IPAddr string
}

func OpenDatabase(path string) {
	dbpath = path
	db, err = badger.Open(badger.DefaultOptions(dbpath))
	if err != nil {
		log.Fatal(err)
	}
	//defer db.Close()
}

func WriteCertRecord(guid string, record CertRecord) error {

	r, err := json.Marshal(record)

	if err != nil {
		return err
	}

	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(guid), []byte(r))
	})

	return err
}

func GetIPAddress() {

}

func GetAllKeys() {
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				fmt.Printf("key=%s, value=%s\n", k, v)
				return nil
			})
			if err != nil {
				fmt.Printf("Error getting value for key:%s\n", k)
			}
		}
		return nil
	})

	if err != nil {
		log.Println(err)
	}
}
