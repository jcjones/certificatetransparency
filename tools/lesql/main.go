// Based on github.com/jmhodges/certificatetransparency/tools/lecsv

package main

import (
	"crypto/x509"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/gorp.v1"

  "bytes"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
  "sync"
	"time"

	"github.com/jcjones/certificatetransparency"
)

var (
	inputPath = flag.String("i", "", "file path to Certificate Transparency log file")
	dbConnect = flag.String("dbConnect", "", "DB Connection String")
	verbose   = flag.Bool("v", false, "verbose output")
  reimport  = flag.Bool("r", false, "reimport all into MySQL")
)

type Certificate struct {
  Serial    string    `db:"serial"`    // The Issuer field of this cert
  Issuer    string    `db:"issuer"`    // The Issuer field of this cert
  Subject   string    `db:"subject"`   // The Subject field of this cert
  NotBefore time.Time `db:"notBefore"` // Date after which this cert should be considered invalid
  NotAfter  time.Time `db:"notAfter"`  // Date after which this cert should be considered invalid
  EntryTime time.Time `db:"entryTime"` // Date after which this cert should be considered invalid
}

type SubjectName struct {
  Name   string `db:"name"`   // identifier
  Serial string `db:"serial"` // The hex encoding of the SHA-1 hash of a cert containing the identifier
  Issuer string `db:"issuer"` // The Issuer field of this cert
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

func initTables(dbMap *gorp.DbMap) {
  dbMap.AddTableWithName(Certificate{}, "certificate").SetKeys(false, "Serial")
  dbMap.AddTableWithName(SubjectName{}, "name")

  dbMap.CreateTablesIfNotExists()
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("")
	entryFilePath := *inputPath
	dbConnectStr, err := recombineURLForDB(*dbConnect)
	if err != nil {
		log.Fatalf("unable to parse %s: %s", *dbConnect, err)
	}

	if len(entryFilePath) == 0 || len(dbConnectStr) == 0 {
		flag.Usage()
		os.Exit(2)
	}

  fileHandle, err := os.OpenFile(entryFilePath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatalf("unable to open %#v: %s", entryFilePath, err)
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
	initTables(dbMap)

  entriesFile, offset, length, startingOffset, err := downloadLog(fileHandle)
  if err != nil {
    log.Fatalf("error while searching CT entries file: %s", err)
  }

  // Reimport all entries
  if (*reimport) {
    startingOffset = 0
  }

  if (offset != length || *reimport) {
    _, err = entriesFile.Seek(int64(startingOffset), 0)
    if err != nil {
      log.Fatalf("unable to seek to %d in %#v: %s", startingOffset, entryFilePath, err)
    }

    if (*verbose) {
      fmt.Printf("Seeked to %d len %d in %#v\n", startingOffset, length, entryFilePath)
    }

    err = processLog(dbMap, entriesFile)
    if err != nil {
      log.Fatalf("error while searching CT entries file: %s", err)
    }
  }
}

func clearLine() {
  fmt.Printf("\x1b[80D\x1b[2K")
}

func displayProgress(statusChan chan certificatetransparency.OperationStatus, wg *sync.WaitGroup) {
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

    for {
      select {
      case status, ok = <-statusChan:
        if !ok {
          return
        }
      case <-ticker.C:
        symbolIndex = (symbolIndex + 1) % len(symbols)
      }

      clearLine()
      fmt.Printf("%s %.1f%% (%d of %d)", symbols[symbolIndex], status.Percentage(), status.Current, status.Length)
    }
  }()
}

func downloadLog(fileHandle *os.File) (*certificatetransparency.EntriesFile, uint64, uint64, int64, error) {
  entriesFile := certificatetransparency.EntriesFile{fileHandle}

  fmt.Printf("Counting existing entries... ")
  count, err := entriesFile.Count()
  if err != nil {
    err = fmt.Errorf("Failed to read entries file: %s", err)
    return nil, 0, 0, 0, err
  }
  fmt.Printf("%d\n", count)

  // Get the starting offset
  startingOffset, err := entriesFile.Seek(0, 1)
  if err != nil {
    return nil, 0, 0, 0, err
  }

  certlyPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2M
NvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==
-----END PUBLIC KEY-----`

  ctLog, err := certificatetransparency.NewLog("https://log.certly.io", certlyPEM)
  if err != nil {
    return nil, 0, 0, 0, err
  }
  fmt.Printf("Fetching signed tree head... ")
  sth, err := ctLog.GetSignedTreeHead()

  if err != nil {
    return nil, 0, 0, 0, err
  }
  fmt.Printf("%d total entries at %s\n", sth.Size, sth.Time.Format(time.ANSIC))
  if count == sth.Size {
    fmt.Printf("Nothing to do\n")
    return &entriesFile, count, sth.Size, startingOffset, nil
  }

  statusChan := make(chan certificatetransparency.OperationStatus, 1)
  wg := new(sync.WaitGroup)
  displayProgress(statusChan, wg)
  _, err = ctLog.DownloadRange(fileHandle, statusChan, count, sth.Size)
  wg.Wait()

  clearLine()
  if err != nil {
    err = fmt.Errorf("Error while downloading: %s", err)
    return nil, 0, 0, 0, err
  }

  fmt.Printf("Hashing tree\n")
  entriesFile.Seek(0, 0)
  statusChan = make(chan certificatetransparency.OperationStatus, 1)
  wg = new(sync.WaitGroup)
  displayProgress(statusChan, wg)
  treeHash, err := entriesFile.HashTree(statusChan, sth.Size)
  wg.Wait()

  clearLine()
  if err != nil {
    err = fmt.Errorf("Error hashing tree: %s", err)
    return nil, 0, 0, 0, err
  }
  if !bytes.Equal(treeHash[:], sth.Hash) {
    err = fmt.Errorf("Hashes do not match! Calculated: %x, STH contains %x", treeHash, sth.Hash)
    return nil, 0, 0, 0, err
  }

  return &entriesFile, count, sth.Size, startingOffset, nil
}

func processLog(dbMap *gorp.DbMap, ef *certificatetransparency.EntriesFile) (error) {
  fmt.Printf("Importing entries into DB...\n")

	err := ef.Map(func(ep *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		cert, err := x509.ParseCertificate(ep.Entry.X509Cert)
		if err != nil {
			return
		}

    // Skip non-LE entries
		if !strings.HasPrefix(cert.Issuer.CommonName, "Let's Encrypt Authority") {
			return
		}

		serialNum := fmt.Sprintf("%036x", cert.SerialNumber)

		certObj, err := dbMap.Get(Certificate{}, serialNum)
		if err != nil {
			log.Fatalf("Could not query for serial %s: %s", serialNum, err)
		}
		if certObj != nil {
			// Already in DB. Skip.
      if *verbose {
        fmt.Println(fmt.Sprintf("Skipping %s (index %d, offset %d) %#v", serialNum, ep.Index, ep.Offset, cert.Subject.CommonName))
      }
			return
		}

    if *verbose {
      fmt.Println(fmt.Sprintf("Processing %s (index %d, offset %d) %#v", serialNum, ep.Index, ep.Offset, cert.Subject.CommonName))
    }

		certObj = &Certificate{
			Serial:    serialNum,
			Issuer:    cert.Issuer.CommonName,
			Subject:   cert.Subject.CommonName,
			NotBefore: cert.NotBefore.UTC(),
			NotAfter:  cert.NotAfter.UTC(),
			EntryTime: ep.Entry.Time.UTC(),
		}
		err = dbMap.Insert(certObj)
		if err != nil {
			log.Fatalf("unable to insert: %#v: %s", certObj, err)
		}

		// De-dupe just in case.
		names := make(map[string]struct{})
		if cert.Subject.CommonName != "" {
			names[cert.Subject.CommonName] = struct{}{}
		}
		for _, name := range cert.DNSNames {
			names[name] = struct{}{}
		}

		// Loop and insert into the DB
		for name, _ := range names {
			nameObj := &SubjectName{
				Name:   name,
				Serial: serialNum,
				Issuer: cert.Issuer.CommonName,
			}
			err = dbMap.Insert(nameObj)
			if err != nil {
				log.Fatalf("unable to insert: %#v: %s", nameObj, err)
			}
		}

		if err != nil {
			return
		}
	})
  return err
}