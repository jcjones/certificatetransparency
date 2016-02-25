/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jmhodges/certificatetransparency/tools/lecsv

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/go-gorp/gorp"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/jcjones/ct-sql/censysdata"
	"github.com/jcjones/ct-sql/sqldb"
)

var (
	logUrl     = flag.String("log", "", "URL of the CT Log")
	censysPath = flag.String("censysJson", "", "Path to a Censys.io certificate json dump")
	dbConnect  = flag.String("dbConnect", "", "DB Connection String")
	verbose    = flag.Bool("v", false, "verbose output")
  fullCerts  = flag.Bool("fullCerts", false, "store full DER-encoded certificates in a certificateraw table")
	offset     = flag.Uint64("offset", 0, "offset from the beginning")
	offsetByte = flag.Uint64("offsetByte", 0, "byte offset from the beginning, only for censysJson and not compatible with offset")
	limit      = flag.Uint64("limit", 0, "limit processing to this many entries")
	reproNames = flag.Bool("reprocessNames", false, "reprocess names")
)

// OperationStatus contains the current state of a large operation (i.e.
// download or tree hash).
type OperationStatus struct {
	// Start contains the requested starting index of the operation.
	Start int64
	// Current contains the greatest index that has been processed.
	Current int64
	// Length contains the total number of entries.
	Length int64
}

func (status OperationStatus) Percentage() float32 {
	total := float32(status.Length - status.Start)
	done := float32(status.Current - status.Start)

	if total == 0 {
		return 100
	}
	return done * 100 / total
}

// Taken from Boulder
func recombineURLForDB(dbConnect string) (string, error) {
	dbConnect = strings.TrimSpace(dbConnect)
	dbURL, err := url.Parse(dbConnect)
	if err != nil {
		return "", err
	}

	if dbURL.Scheme != "mysql+tcp" {
		format := "given database connection string was not a mysql+tcp:// URL, was %#v"
		return "", fmt.Errorf(format, dbURL.Scheme)
	}

	dsnVals, err := url.ParseQuery(dbURL.RawQuery)
	if err != nil {
		return "", err
	}

	dsnVals.Set("parseTime", "true")

	// Required to make UPDATE return the number of rows matched,
	// instead of the number of rows changed by the UPDATE.
	dsnVals.Set("clientFoundRows", "true")

	// Ensures that MySQL/MariaDB warnings are treated as errors. This
	// avoids a number of nasty edge conditions we could wander
	// into. Common things this discovers includes places where data
	// being sent had a different type than what is in the schema,
	// strings being truncated, writing null to a NOT NULL column, and
	// so on. See
	// <https://dev.mysql.com/doc/refman/5.0/en/sql-mode.html#sql-mode-strict>.
	dsnVals.Set("strict", "true")

	user := dbURL.User.Username()
	passwd, hasPass := dbURL.User.Password()
	dbConn := ""
	if user != "" {
		dbConn = url.QueryEscape(user)
	}
	if hasPass {
		dbConn += ":" + passwd
	}
	dbConn += "@tcp(" + dbURL.Host + ")"
	return dbConn + dbURL.EscapedPath() + "?" + dsnVals.Encode(), nil
}

func clearLine() {
	fmt.Printf("\x1b[80D\x1b[2K")
}

func displayProgress(statusChan chan OperationStatus, wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()
		symbols := []string{"|", "/", "-", "\\"}
		symbolIndex := 0

		status, ok := <-statusChan
		if !ok {
			return
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		isInteractive := strings.Contains(os.Getenv("TERM"), "xterm") || strings.Contains(os.Getenv("TERM"), "screen")

		if !isInteractive {
			ticker.Stop()
		}

		for {
			select {
			case status, ok = <-statusChan:
				if !ok {
					return
				}
			case <-ticker.C:
				symbolIndex = (symbolIndex + 1) % len(symbols)
			}

			if isInteractive {
				clearLine()
				fmt.Printf("%s %.1f%% (%d of %d)", symbols[symbolIndex], status.Percentage(), status.Current, status.Length)
			} else {
				fmt.Println(fmt.Printf("%.1f%% (%d of %d)", status.Percentage(), status.Current, status.Length))
			}
		}
	}()
}

func insertCTWorker(entries <-chan ct.LogEntry, db *sqldb.EntriesDatabase, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	for ep := range entries {
		err := db.InsertCTEntry(&ep)
		if err != nil {
			log.Printf("Problem inserting certificate: index: %d log: %s error: %s", ep.Index, *logUrl, err)
		}
	}
}

func insertCensysWorker(entries <-chan censysdata.CensysEntry, db *sqldb.EntriesDatabase, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	for ep := range entries {
		if ep.Valid_nss {
			err := db.InsertCensysEntry(&ep)
			if err != nil {
				log.Printf("Problem inserting certificate: index: %d error: %s", ep.Offset, err)
			}
		}
	}
}

// DownloadRange downloads log entries from the given starting index till one
// less than upTo. If status is not nil then status updates will be written to
// it until the function is complete, when it will be closed. The log entries
// are provided to an output channel.
func downloadCTRangeToChannel(ctLog *client.LogClient, outEntries chan<- ct.LogEntry,
	status chan<- OperationStatus, start, upTo int64) (int64, error) {
	if outEntries == nil {
		return 0, fmt.Errorf("No output channel provided")
	}
	defer close(outEntries)
	if status != nil {
		defer close(status)
	}

	index := start
	for index < upTo {
		if status != nil {
			status <- OperationStatus{start, index, upTo}
		}

		max := index + 2000
		if max >= upTo {
			max = upTo - 1
		}
		rawEnts, err := ctLog.GetEntries(index, max)
		if err != nil {
			return index, err
		}

		for _, ent := range rawEnts {
			outEntries <- ent
			if (ent.Index) != index {
				return index, fmt.Errorf("Index mismatch, local: %v, remote: %v", index, ent.Index)
			}

			index++
		}
	}

	return index, nil
}

func downloadLog(ctLogUrl *url.URL, ctLog *client.LogClient, db *sqldb.EntriesDatabase) error {
	if *offsetByte > 0 {
		return fmt.Errorf("Cannot set offsetByte for CT log downloads")
	}

	fmt.Printf("Fetching signed tree head... ")
	sth, err := ctLog.GetSTH()
	if err != nil {
		return err
	}

	// Set pointer in DB, now that we've verified the log works
	err = db.SetLog(fmt.Sprintf("%s%s", ctLogUrl.Host, ctLogUrl.Path))
	if err != nil {
		log.Fatalf("unable to set Certificate Log: %s", err)
	}

	var origCount uint64
	// Now we're OK to use the DB
	if *offset > 0 {
		log.Printf("Starting from offset %d", *offset)
		origCount = *offset
	} else {
		log.Printf("Counting existing entries... ")
		origCount, err = db.Count()
		if err != nil {
			err = fmt.Errorf("Failed to read entries file: %s", err)
			return err
		}
	}

	fmt.Printf("%d total entries at %s\n", sth.TreeSize, sqldb.Uint64ToTimestamp(sth.Timestamp).Format(time.ANSIC))
	if origCount == sth.TreeSize {
		fmt.Printf("Nothing to do\n")
		return nil
	}

	endPos := sth.TreeSize
	if *limit > 0 && endPos > origCount+*limit {
		endPos = origCount + *limit
	}

	fmt.Printf("Going from %d to %d\n", origCount, endPos)

	entryChan := make(chan ct.LogEntry, 100)
	statusChan := make(chan OperationStatus, 1)
	wg := new(sync.WaitGroup)

	displayProgress(statusChan, wg)
	for i := 0; i < runtime.NumCPU(); i++ {
		go insertCTWorker(entryChan, db, wg)
	}
	_, err = downloadCTRangeToChannel(ctLog, entryChan, statusChan, int64(origCount), int64(endPos))
	wg.Wait()

	clearLine()
	if err != nil {
		err = fmt.Errorf("Error while downloading: %s", err)
		return err
	}

	return nil
}

func processImporter(importer *censysdata.Importer, db *sqldb.EntriesDatabase, wg *sync.WaitGroup) error {
	entryChan := make(chan censysdata.CensysEntry, 100)
	defer close(entryChan)
	statusChan := make(chan OperationStatus, 1)
	defer close(statusChan)
	wg.Add(1)
	defer wg.Done()

	displayProgress(statusChan, wg)
	for i := 0; i < runtime.NumCPU(); i++ {
		go insertCensysWorker(entryChan, db, wg)
	}

	startOffset := *offsetByte
	maxOffset, err := importer.Size()
	if err != nil {
		return err
	}

	//
	// Fast forward
	//
	if *offset > 0 && *offsetByte > 0 {
		return fmt.Errorf("You may not set both offset and offsetByte")
	}

	if *offset > 0 {
		err = importer.SeekLine(*offset)
		if err != nil {
			return err
		}
	}

	if *offsetByte > 0 {
		err = importer.SeekByte(*offsetByte)
		if err != nil {
			return err
		}
	}

	log.Printf("Starting import from offset=%d, line_limit=%d / size=%d.", importer.ByteOffset(), *limit, maxOffset)

	// We've already fast-forwarded, so start at 0.
	for count := uint64(0); ; count++ {
		if *limit > uint64(0) && count >= *limit {
			return nil
		}
		ent, err := importer.NextEntry()
		if err != nil || ent == nil {
			return err
		}
		if count%128 == 0 {
			statusChan <- OperationStatus{int64(startOffset), int64(ent.Offset), int64(maxOffset)}
		}
		entryChan <- *ent
	}

	return nil
}

func reprocessNames(db *sqldb.EntriesDatabase, wg *sync.WaitGroup) error {
	statusChan := make(chan OperationStatus, 1)
	defer close(statusChan)
	wg.Add(1)
	defer wg.Done()

	displayProgress(statusChan, wg)

	certIDs, err := db.GetNamesWithoutRegisteredDomains(*limit)
	if err != nil {
		return err
	}

	for count, id := range certIDs {
		if count%1024 == 0 {
			statusChan <- OperationStatus{int64(0), int64(count), int64(len(certIDs))}
		}

		err = db.ReprocessRegisteredDomainsForCertId(id)

		if err != nil {
			log.Printf("Problem reprocessing certificate: certID: %d error: %s", id, err)
		}
	}

	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("")
	dbConnectStr, err := recombineURLForDB(*dbConnect)
	if err != nil {
		log.Printf("unable to parse %s: %s", *dbConnect, err)
	}

	if len(dbConnectStr) == 0 || (censysPath == nil && logUrl == nil) {
		flag.Usage()
		os.Exit(2)
	}

	db, err := sql.Open("mysql", dbConnectStr)
	if err != nil {
		log.Fatalf("unable to open SQL: %s: %s", dbConnectStr, err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("unable to ping SQL: %s: %s", dbConnectStr, err)
	}

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	dbMap := &gorp.DbMap{Db: db, Dialect: dialect}
	entriesDb := &sqldb.EntriesDatabase{DbMap: dbMap, Verbose: *verbose, FullCerts: *fullCerts}
	err = entriesDb.InitTables()
	if err != nil {
		log.Fatalf("unable to prepare SQL: %s: %s", dbConnectStr, err)
	}

	if *reproNames {
		wg := new(sync.WaitGroup)
		err = reprocessNames(entriesDb, wg)
		if err != nil {
			log.Fatalf("error while reprocessing the names: %s", err)
		}
		wg.Wait()
		os.Exit(0)
	}

	if logUrl != nil && len(*logUrl) > 5 {
		ctLogUrl, err := url.Parse(*logUrl)
		if err != nil {
			log.Fatalf("unable to set Certificate Log: %s", err)
		}

		ctLog := client.New(*logUrl)

		err = downloadLog(ctLogUrl, ctLog, entriesDb)
		if err != nil {
			log.Fatalf("error while updating CT entries: %s", err)
		}

		os.Exit(0)
	}

	if censysPath != nil && len(*censysPath) > 5 {
		importer := &censysdata.Importer{}
		err = importer.OpenFile(*censysPath)
		if err != nil {
			log.Fatalf("unable to open Censys file: %s", err)
		}
		defer importer.Close()

		wg := new(sync.WaitGroup)
		err := processImporter(importer, entriesDb, wg)

		if err != nil {
			log.Fatalf("error while running importer: %s", err)
		}

		wg.Wait()
		os.Exit(0)
	}

	// Didn't include a mandatory action, so print usage and exit.
	flag.Usage()
	os.Exit(2)
}
