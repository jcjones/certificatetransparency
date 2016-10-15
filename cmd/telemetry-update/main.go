/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jmhodges/certificatetransparency/tools/lecsv

package main

import (
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/go-gorp/gorp"
	"github.com/jcjones/ct-sql/firefox-telemetry"
	"github.com/jcjones/ct-sql/sqldb"
	"github.com/jcjones/ct-sql/utils"
)

var (
	config = utils.NewCTConfig()
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	dbConnectStr, err := sqldb.RecombineURLForDB(*config.DbConnect)
	if err != nil {
		log.Printf("unable to parse %s: %s", *config.DbConnect, err)
	}

	if len(dbConnectStr) == 0 {
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

	dialect := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"}
	dbMap := &gorp.DbMap{Db: db, Dialect: dialect}
	entriesDb := &sqldb.EntriesDatabase{DbMap: dbMap,
		Verbose: *config.Verbose, KnownIssuers: make(map[string]int)}
	err = entriesDb.InitTables()
	if err != nil {
		log.Fatalf("unable to prepare SQL DB. dbConnectStr=%s: %s", dbConnectStr, err)
	}

	// Get a Firefox Telemetry client
	client, err := firefoxtelemetry.NewClient()
	if err != nil {
		log.Fatalf("unable to open Telemetry Client: %s", err)
	}

	// Find the versions and dates we can query
	versionList, err := client.GetVersions("release")
	if err != nil {
		log.Fatalf("unable to get telemetry versions: %s", err)
	}
	// log.Printf("%+v", versionList)

	// Filter on the oldest date we want
	oldestDate := time.Now().AddDate(0, 0, -1**config.HistoricalDays)

	versionDateMap := make(map[string][]time.Time)
	for _, obj := range versionList {
		timeObj, err := time.Parse(firefoxtelemetry.TelemetryDateFormat, obj.Date)
		if err != nil {
			// log.Fatalf("unable to parse date in GetVersions: %s", err)
			continue
		}
		if timeObj.Before(oldestDate) {
			continue
		}
		versionDateMap[obj.Version] = append(versionDateMap[obj.Version], timeObj)
	}

	type TelemetryResult struct {
		LoadsTLS   int
		LoadsTotal int
	}

	dateDataMap := make(map[time.Time]TelemetryResult)

	for versionNumber, dateList := range versionDateMap {
		// Obtain data from Firefox Telemetry
		data, err := client.GetAggregates("HTTP_PAGELOAD_IS_SSL", "release", dateList, versionNumber)
		if err != nil {
			log.Printf("unable to get telemetry: %s", err)
			continue
		}

		// log.Printf("VERSION %s DATES: [%s] Result:\n%+v", versionNumber, dateList, data)

		for _, d := range data.Data {
			dateObj, err := time.Parse(firefoxtelemetry.TelemetryDateFormat, d.Date)
			if err != nil {
				log.Fatalf("unable to parse date in GetAggregates: %s", err)
			}

			entry, exists := dateDataMap[dateObj]
			if !exists {
				entry = TelemetryResult{}
			}

			entry.LoadsTLS += d.Histogram[1]
			entry.LoadsTotal += d.Histogram[0] + d.Histogram[1]

			dateDataMap[dateObj] = entry
		}
	}

	for dateObj, result := range dateDataMap {
		if *config.Verbose {
			percentTLS := (float64)(result.LoadsTLS) / (float64)(result.LoadsTotal)
			log.Printf("%s: (%d / %d) = %f percent was TLS\n", dateObj, result.LoadsTLS, result.LoadsTotal, percentTLS)
		}

		err = entriesDb.InsertOrUpdatePageloadIsTLS(dateObj, result.LoadsTLS, result.LoadsTotal)
		if err != nil {
			log.Fatalf("unable to update DB: %s", err)
		}
	}
}
