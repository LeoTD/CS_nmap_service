package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteInsertAndSelect(t *testing.T) {
	var db *sql.DB = DatabaseSetup("./test.db")
	defer db.Close()
	// db, err := sql.Open("sqlite3", "./test.db")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// defer db.Close()

	// stmt, err := db.Prepare(`DROP TABLE IF EXISTS scanhistory;`)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// _, err = stmt.Exec()
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// stmt, err = db.Prepare(`CREATE TABLE scanhistory(
	// 	id INTEGER PRIMARY KEY AUTOINCREMENT,
 	// 	sid INTEGER NOT NULL,
 	// 	hostname TEXT NOT NULL,
 	// 	address TEXT NOT NULL,
 	// 	timestamp INT NOT NULL,
	// 	ports TEXT NOT NULL
	// )`)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// _, err = stmt.Exec()
	// if err != nil {
	// 	t.Fatal(err)
	// }

	InsertEntry(db, Entry{sid: 0, Hostname: "google.com", Address: "1.0.0.0", Ports: "80/tcp open http", Timestamp: 0})
	InsertEntry(db, Entry{sid: 0, Hostname: "amazon.com", Address: "2.0.0.0", Ports: "80/tcp open http", Timestamp: 0})
	InsertEntry(db, Entry{sid: 0, Hostname: "amazon.com", Address: "2.0.0.0", Ports: "80/tcp open http", Timestamp: 0})
	InsertEntry(db, Entry{sid: 0, Hostname: "amazon.com", Address: "2.0.0.0", Ports: "80/tcp open http", Timestamp: 0})
	InsertEntry(db, Entry{sid: 0, Hostname: "youtube.com", Address: "3.0.0.0", Ports: "80/tcp open http\n433/tcp open https", Timestamp: 0})

	rows, err := SelectMatchingHistory(db, Entry{sid: 0, Hostname: "amazon.com", Address: "2.0.0.0", Ports: "80/tcp open http", Timestamp: 0})
	if err != nil {
		t.Fatalf("Database error.")
	}
	defer rows.Close()

	entries := make([]*Entry, 0)
	for rows.Next() {
		new_entry := new(Entry)
		var entry_id int
		err = rows.Scan(&entry_id, &new_entry.sid, &new_entry.Hostname, &new_entry.Address, &new_entry.Ports, &new_entry.Timestamp)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, new_entry)
	}

	for _, e := range entries {
		fmt.Printf("%s: %s -- %s %d\n", e.Hostname, e.Address, e.Ports, e.Timestamp)
	}
}

func TestNmapScanner(t *testing.T) {
	result, err := ScanHost("google.com")
	if err != nil {
		t.Fatal(err)
	}

	portString := ""
	for _, port := range result.Ports {
		portString += fmt.Sprintf("Port %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
	}

	var e Entry = Entry{
		sid: 			0,
		Address:		result.Addresses[0].String(),
		Hostname:		result.Hostnames[0].Name,
		Ports:			portString,
		Timestamp:		0,
	}

	j, err := json.Marshal(e)
    if err != nil {
        fmt.Println(err)
        return
    }

	fmt.Println(string(j))
}