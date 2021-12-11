package badgermgr

import (
	"log"

	badger "github.com/dgraph-io/badger/v3"
)

var dbpath string

func OpenDatabase(path string) {
	dbpath = path
	db, err := badger.Open(badger.DefaultOptions(dbpath))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
}
