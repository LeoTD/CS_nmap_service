package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"text/template"
	"time"

	"github.com/Ullaakut/nmap/v2"
	_ "github.com/mattn/go-sqlite3"
)

var pageTemplate *template.Template

var globalDBGuard sync.Mutex
var db *sql.DB

// TODO: Store more information about each port. (One to many database table?)
type Entry struct {
	sid			int
	Hostname	string		`json:"hostname"`
	Address		string		`json:"addr"`
	Timestamp	int			`json:"timestamp"`
	Ports		string		`json:"ports"`
}

func init() {
	// confirm nmap installation:
	fmt.Printf("Check nmap installation... ")
	_, err := exec.LookPath("nmap")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("OK.\n")

	// prep database
	fmt.Printf("Prepping database... ")
	db = DatabaseSetup("./scan.db")
	fmt.Printf("OK.\n")

	// initialitze web page template
	fmt.Printf("Prepping page templates... ")
	pageTemplate = template.Must(template.ParseGlob("templates/*"))
	fmt.Printf("OK.\n")
}

func main() {
	// Close database on program exit.
	defer db.Close()

	// start the server
	fmt.Printf("Starting Server...\n")

	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/", mainPage)

	// TODO: as a service
	// http.HandleFunc("/aaS", service)
    
	const serverPort string = ":8080"
	http.ListenAndServe(serverPort, nil)
	
}

func mainPage(w http.ResponseWriter, req *http.Request) {
	// TODO: Session IDs. Check for existing session else make one.

	err := pageTemplate.ExecuteTemplate(w, "mainPage.gohtml", nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	h := req.FormValue("hostname")

	if len(h) > 0 {
		// TODO: split string by delimiter. launch gorutines to scan each hostname.
		// TODO: hostname validation
		result, err := ScanHost(h)
		if err != nil {
			log.Fatal(err)
		}

		// create a new entry for the db
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

		// Lock db mutex, then add entry to db.
		globalDBGuard.Lock()
		InsertEntry(db, e)

		// before returning the db, perform query for all scan to that hostname.
		rows, err := SelectMatchingHistory(db, e)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		// scan through selected rows, populate entries array
		var entry_id int
		entries := make([]*Entry, 0)
		for rows.Next() {
			new_entry := new(Entry)
			err = rows.Scan(&entry_id, &new_entry.sid, &new_entry.Hostname, &new_entry.Address, &new_entry.Ports, &new_entry.Timestamp)
			if err != nil {
				log.Fatal(err)
			}
			entries = append(entries, new_entry)
		}

		// give back the db and clean up
		rows.Close()
		globalDBGuard.Unlock()

		// send additional html elements to the page based on entries in array
		for _, e := range entries {
			err = pageTemplate.ExecuteTemplate(w, "appendResult.gohtml", e)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s: %s -- %s %d\n", e.Hostname, e.Address, e.Ports, e.Timestamp)
		}
	}
}


//
// 	-------- NMAP wrapper:
//

// Performs one scan on {hostname} (nmap.exe -p 1-1000 {hostname}) Reports results.
func ScanHost(hostname string) (res *nmap.Host, err error) {
	// give up after 60 seconds.
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    scanner, err := nmap.NewScanner(
        nmap.WithTargets(hostname),
        nmap.WithPorts("1-1000"),
        nmap.WithContext(ctx),
    )
    if err != nil {
        return nil, err
    }

    result, warnings, err := scanner.Run()
    if err != nil {
        return nil, err
    }

    if warnings != nil {
        log.Printf("Warnings: \n %v", warnings)
    }

	host := result.Hosts[0]

	// check if dns resolved hostname, and any connection was established.
	if len(host.Ports) == 0 || len(host.Addresses) == 0 {
		return nil, errors.New("scan failure")
	}

	fmt.Printf("Nmap done: %s scanned in %3f seconds\n", host.Hostnames[0], result.Stats.Finished.Elapsed)

	return &host, nil
}

//
// 	-------- SQL Functions:
//

func DatabaseSetup(db_path string) *sql.DB {
	new_db, err := sql.Open("sqlite3", db_path)
	if err != nil {
		log.Fatal(err)
	}

	stmt, err := db.Prepare(`DROP TABLE IF EXISTS scanhistory;`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = stmt.Exec()
	if err != nil {
		log.Fatal(err)
	}

	stmt, err = db.Prepare(`CREATE TABLE scanhistory(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
 		sid INTEGER NOT NULL,
 		hostname TEXT NOT NULL,
 		address TEXT NOT NULL,
 		timestamp INT NOT NULL,
		ports TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = stmt.Exec()
	if err != nil {
		log.Fatal(err)
	}

	return new_db
}

func InsertEntry(db *sql.DB, e Entry) {
	stmt, err := db.Prepare("INSERT INTO scanhistory(sid, hostname, address, timestamp, ports) values(?,?,?,?, unixepoch() )")
	if err != nil {
		log.Fatal(err)
	}

	_, err = stmt.Exec(e.sid, e.Hostname, e.Address, e.Ports)
	if err != nil {
		log.Fatal(err)
	}
}

func SelectMatchingHistory(db *sql.DB, e Entry) (*sql.Rows, error) {
	stmt, err := db.Prepare("SELECT * FROM scanhistory WHERE sid == ? AND address == ? ORDER BY timestamp DESC")
	if err != nil {
		return nil, err
	}

	res, err := stmt.Query(e.sid, e.Address)
	if err != nil {
		return nil, err
	}

	return res, err
}