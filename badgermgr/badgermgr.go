package badgermgr

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	badger "github.com/dgraph-io/badger/v3"
)

var dbpath string
var ipAddress string
var db *badger.DB
var err error

type CertRecord struct {
	PubKey string
	Token  string
	IPAddr string
}

func OpenDatabase(path string, ip string) {
	dbpath = path
	ipAddress = ip
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

func writeDefaultIPAddress(ip string) error {

	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("currentIPAddress"), []byte(ip))
	})

	return err
}

func getNextIP(ip string) string {

	ipParts := strings.Split(ip, ".")

	part1, err := strconv.Atoi(ipParts[0])
	part2, err := strconv.Atoi(ipParts[1])
	part3, err := strconv.Atoi(ipParts[2])
	part4, err := strconv.Atoi(ipParts[3])

	if err != nil {
		return ""
	}

	if part4 > 254 {
		if part3 > 254 {
			if part2 > 254 {
				return strconv.Itoa(part1+1) + ".0.0.0"
			}
			return strconv.Itoa(part1) + "." + strconv.Itoa(part2+1) + ".0.0"
		}
		return strconv.Itoa(part1) + "." + strconv.Itoa(part2) + "." + strconv.Itoa(part3+1) + ".0"
	}
	return strconv.Itoa(part1) + "." + strconv.Itoa(part2) + "." + strconv.Itoa(part3) + "." + strconv.Itoa(part4+1)
}

func GetIPAddress() string {

	var ip string

	err := db.View(func(txn *badger.Txn) error {

		item, err := txn.Get([]byte("currentIPAddress"))

		if err != nil {
			log.Println("Setting Default IP Address")
			writeDefaultIPAddress(ipAddress)
			ip = ipAddress
			return err
		}

		err = item.Value(func(val []byte) error {

			fmt.Printf("Found default IP: %s\n", val)

			ip = getNextIP(string(val))
			return nil
		})

		return err
	})

	if err != nil {
		log.Println(err)
	}
	writeDefaultIPAddress(ip)
	return ip
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
