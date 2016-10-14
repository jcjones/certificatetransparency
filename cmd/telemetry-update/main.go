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

	// Assemble the dates we want to query
	dates := []time.Time{}
	for i := 1; i < *config.HistoricalDays; i++ {
		dates = append(dates, time.Now().AddDate(0, 0, -i))
	}

	// Obtain data from Firefox Telemetry
	data, err := client.GetAggregates("HTTP_PAGELOAD_IS_SSL", "release", dates)
	if err != nil {
		log.Fatalf("unable to get telemetry: %s", err)
	}

	for _, d := range data.Data {
		isTLS := d.Histogram[1]
		count := d.Histogram[0] + d.Histogram[1]
		percentTLS := (float64)(isTLS) / (float64)(count)
		dateObj, err := time.Parse(firefoxtelemetry.TelemetryDateFormat, d.Date)
		if err != nil {
			log.Fatalf("unable to parse date: %s", err)
		}

		if *config.Verbose {
			log.Printf("%s: (%d / %d) = %f percent was TLS\n", dateObj, isTLS, count, percentTLS)
		}

		err = entriesDb.InsertOrUpdatePageloadIsTLS(dateObj, isTLS, count)
		if err != nil {
			log.Fatalf("unable to update DB: %s", err)
		}
	}
}
