/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jmhodges/certificatetransparency/tools/lecsv

package main

import (
	"database/sql"
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
	"github.com/jcjones/ct-sql/utils"
)

var (
	config = utils.NewCTConfig()
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

		// Speed statistics
		progressMonitor := utils.NewProgressMonitor()

		for {
			select {
			case status, ok = <-statusChan:
				if !ok {
					return
				}

				// Track speed statistics
				progressMonitor.UpdateCount(status.Current)
				progressMonitor.UpdateLength(status.Length)
			case <-ticker.C:
				symbolIndex = (symbolIndex + 1) % len(symbols)
			}

			// Display the line
			statusLine := fmt.Sprintf("%.1f%% (%d of %d) Rate: %s", status.Percentage(), status.Current, status.Length, progressMonitor)

			if isInteractive {
				clearLine()
				fmt.Printf("%s %s", symbols[symbolIndex], statusLine)
			} else {
				fmt.Println(statusLine)
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
			log.Printf("Problem inserting certificate: index: %d log: %s error: %s", ep.Index, *config.LogUrl, err)
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
	if *config.OffsetByte > 0 {
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
	if *config.Offset > 0 {
		log.Printf("Starting from offset %d", *config.Offset)
		origCount = *config.Offset
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
	if *config.Limit > 0 && endPos > origCount+*config.Limit {
		endPos = origCount + *config.Limit
	}

	fmt.Printf("Going from %d to %d\n", origCount, endPos)

	entryChan := make(chan ct.LogEntry, 100)
	statusChan := make(chan OperationStatus, 1)
	wg := new(sync.WaitGroup)

	displayProgress(statusChan, wg)
	numWorkers := *config.NumThreads * runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
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

func processImporter(importer censysdata.Importer, db *sqldb.EntriesDatabase, wg *sync.WaitGroup) error {
	entryChan := make(chan censysdata.CensysEntry, 100)
	defer close(entryChan)
	statusChan := make(chan OperationStatus, 1)
	defer close(statusChan)
	wg.Add(1)
	defer wg.Done()

	displayProgress(statusChan, wg)
	numWorkers := *config.NumThreads * runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		go insertCensysWorker(entryChan, db, wg)
	}

	startOffset := *config.OffsetByte

	//
	// Fast forward
	//
	if *config.Offset > 0 && *config.OffsetByte > 0 {
		return fmt.Errorf("You may not set both offset and offsetByte")
	}

	if *config.Offset > 0 {
		err := importer.SeekLine(*config.Offset)
		if err != nil {
			return err
		}
	}

	if *config.OffsetByte > 0 {
		err := importer.SeekByte(*config.OffsetByte)
		if err != nil {
			return err
		}
	}

	var maxOffset uint64

	log.Printf("Starting import from offset=%d, line_limit=%d", importer.ByteOffset(), *config.Limit)

	// We've already fast-forwarded, so start at 0.
	for count := uint64(0); ; count++ {
		if *config.Limit > uint64(0) && count >= *config.Limit {
			return nil
		}
		ent, err := importer.NextEntry()
		if err != nil || ent == nil {
			return err
		}
		if count%128 == 0 {
			// Lazily obtain the max offset
			if maxOffset < 1 {
				maxOffset, err = importer.Size()
				if err != nil {
					return err
				}
			}

			statusChan <- OperationStatus{int64(startOffset), int64(ent.Offset), int64(maxOffset)}
		}
		entryChan <- *ent
	}

	return nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	dbConnectStr, err := sqldb.RecombineURLForDB(*config.DbConnect)
	if err != nil {
		log.Printf("unable to parse %s: %s", *config.DbConnect, err)
	}

	if len(dbConnectStr) == 0 || (config.CensysPath == nil && config.LogUrl == nil) {
		config.Usage()
		os.Exit(2)
	}

	db, err := sql.Open("mysql", dbConnectStr)
	if err != nil {
		log.Fatalf("unable to open SQL: %s: %s", dbConnectStr, err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("unable to ping SQL: %s: %s", dbConnectStr, err)
	}

	var certFolderDB *utils.FolderDatabase
	if config.CertPath != nil && len(*config.CertPath) > 0 {
		certFolderDB, err = utils.NewFolderDatabase(*config.CertPath, 0444, *config.CertsPerFolder)
		if err != nil {
			log.Fatalf("unable to open Certificate Path: %s: %s", config.CertPath, err)
		}
	}

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	dbMap := &gorp.DbMap{Db: db, Dialect: dialect}
	entriesDb := &sqldb.EntriesDatabase{DbMap: dbMap,
		Verbose: *config.Verbose, FullCerts: certFolderDB,
		KnownIssuers: make(map[string]int)}
	err = entriesDb.InitTables()
	if err != nil {
		log.Fatalf("unable to prepare SQL: %s: %s", dbConnectStr, err)
	}

	if config.LogUrl != nil && len(*config.LogUrl) > 5 {
		ctLogUrl, err := url.Parse(*config.LogUrl)
		if err != nil {
			log.Fatalf("unable to set Certificate Log: %s", err)
		}

		ctLog := client.New(*config.LogUrl, nil)

		log.Printf("Starting download from log %s, fullCerts=%t\n", ctLogUrl, (certFolderDB != nil))

		err = downloadLog(ctLogUrl, ctLog, entriesDb)
		if err != nil {
			log.Fatalf("error while updating CT entries: %s", err)
		}

		os.Exit(0)
	}

	var importer censysdata.Importer
	if config.CensysUrl != nil && len(*config.CensysUrl) > 5 {
		urlImporter, err := censysdata.OpenURL(*config.CensysUrl)
		if err != nil {
			log.Fatalf("unable to open Censys URL: %s", err)
		}
		importer = urlImporter
	} else if config.CensysPath != nil && len(*config.CensysPath) > 5 {
		fileImporter, err := censysdata.OpenFile(*config.CensysPath)
		if err != nil {
			log.Fatalf("unable to open Censys file: %s", err)
		}
		importer = fileImporter
		defer fileImporter.Close()
	}

	if importer != nil {
		log.Printf("Starting Censys Import, using %s, fullCerts=%t\n", importer.String(), (certFolderDB != nil))

		wg := new(sync.WaitGroup)
		err = processImporter(importer, entriesDb, wg)

		if err != nil {
			log.Fatalf("error while running importer: %s", err)
		}

		wg.Wait()
		os.Exit(0)
	}

	// Didn't include a mandatory action, so print usage and exit.
	config.Usage()
	os.Exit(2)
}
