/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Implements the CT Log as a SQL Database

package sqldb

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-gorp/gorp"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/x509"
	"github.com/jcjones/ct-sql/censysdata"
	"github.com/jcjones/ct-sql/utils"
	"github.com/jpillora/backoff"
	"golang.org/x/net/publicsuffix"
)

type Certificate struct {
	CertID    uint64    `db:"certID, primarykey, autoincrement"` // Internal Cert Identifier
	Serial    string    `db:"serial"`                            // The serial number of this cert
	IssuerID  int       `db:"issuerID"`                          // The Issuer of this cert
	Subject   string    `db:"subject"`                           // The Subject field of this cert
	NotBefore time.Time `db:"notBefore"`                         // Date before which this cert should be considered invalid
	NotAfter  time.Time `db:"notAfter"`                          // Date after which this cert should be considered invalid
}

type Issuer struct {
	IssuerID       int    `db:"issuerID, primarykey, autoincrement"` // Internal Issuer ID
	CommonName     string `db:"commonName"`                          // Issuer CN
	AuthorityKeyId string `db:"authorityKeyID"`                      // Authority Key ID
}

type SubjectName struct {
	NameID uint64 `db:"nameID, primarykey, autoincrement"` // Internal Name Identifier
	CertID uint64 `db:"certID"`                // Internal Cert Identifier
	Name   string `db:"name"`                  // identifier
}

type RegisteredDomain struct {
	CertID uint64 `db:"certID"` // Internal Cert Identifier
	ETLD   string `db:"etld"`   // effective top-level domain
	Label  string `db:"label"`  // first label
	Domain string `db:"domain"` // eTLD+first label
}

type CertificateLog struct {
	LogID int    `db:"logID, primarykey, autoincrement"` // Log Identifier (FK to CertificateLog)
	URL   string `db:"url"`                  // URL to the log
}

type CertificateLogEntry struct {
	CertID    uint64    `db:"certID"`    // Internal Cert Identifier (FK to Certificate)
	LogID     int       `db:"logID"`     // Log Identifier (FK to CertificateLog)
	EntryID   uint64    `db:"entryId"`   // Entry Identifier within the log
	EntryTime time.Time `db:"entryTime"` // Date when this certificate was added to the log
}

type CensysEntry struct {
	CertID    uint64    `db:"certID"`    // Internal Cert Identifier (FK to Certificate)
	EntryTime time.Time `db:"entryTime"` // Date when this certificate was imported from Censys.io
}

type ResolvedName struct {
	NameID  uint64    `db:"nameID"` // Internal Name Identifier (FK to Subject Name)
	Time    time.Time `db:"time"`   // Date when this resolution was performed
	Address string    `db:"ipaddr"` // IP address resolved at this name
}

type ResolvedPlace struct {
	NameID    uint64    `db:"nameID"`    // Internal Name Identifier (FK to Subject Name)
	Time      time.Time `db:"time"`      // Date when this resolution was performed
	City      string    `db:"city"`      // Geo: City name
	Country   string    `db:"country"`   // Geo: Country ISO code
	Continent string    `db:"continent"` // Geo: Continent name
}

func Uint64ToTimestamp(timestamp uint64) time.Time {
	return time.Unix(int64(timestamp/1000), int64(timestamp%1000))
}

// Returns true if err is not nil, and is not a Duplicate entry error
func errorIsNotDuplicate(err error) bool {
	if err != nil {
		return strings.Contains(err.Error(), "Duplicate entry") == false
	}
	return false
}

type EntriesDatabase struct {
	DbMap        *gorp.DbMap
	LogId        int
	Verbose      bool
	FullCerts    *utils.FolderDatabase
	IssuerFilter *string
	KnownIssuers map[string]int
	IssuersLock  sync.RWMutex
}

// Taken from Boulder
func RecombineURLForDB(dbConnect string) (string, error) {
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

func (edb *EntriesDatabase) InitTables() error {
	if edb.Verbose {
		edb.DbMap.TraceOn("[gorp]", log.New(os.Stdout, "myapp:", log.Lmicroseconds))
	}

	edb.DbMap.AddTableWithName(CensysEntry{}, "censysentry")
	edb.DbMap.AddTableWithName(CertificateLogEntry{}, "ctlogentry")
	edb.DbMap.AddTableWithName(RegisteredDomain{}, "registereddomain")
	edb.DbMap.AddTableWithName(ResolvedName{}, "resolvedname")
	edb.DbMap.AddTableWithName(ResolvedPlace{}, "resolvedplace")

	edb.DbMap.AddTableWithName(CertificateLog{}, "ctlog").SetKeys(true, "LogID")
	edb.DbMap.AddTableWithName(Certificate{}, "certificate").SetKeys(true, "CertID")
	edb.DbMap.AddTableWithName(Issuer{}, "issuer").SetKeys(true, "IssuerID")
	edb.DbMap.AddTableWithName(SubjectName{}, "name").SetKeys(true, "NameID")

	// All is well, no matter what.
	return nil
}

func (edb *EntriesDatabase) Count() (count uint64, err error) {
	err = edb.DbMap.SelectOne(&count, "SELECT CASE WHEN MAX(e.entryId) IS NULL THEN 0 ELSE MAX(e.entryId)+1 END FROM ctlogentry AS e WHERE e.logID = ?", edb.LogId)
	return
}

func (edb *EntriesDatabase) SetLog(url string) error {
	var certLogObj CertificateLog

	err := edb.DbMap.SelectOne(&certLogObj, "SELECT * FROM ctlog WHERE url = ?", url)
	if err != nil {
		// Couldn't find it. Set the object and insert it.
		certLogObj.URL = url

		err = edb.DbMap.Insert(&certLogObj)
		if err != nil {
			return err
		}
	}

	edb.LogId = certLogObj.LogID
	return nil
}

func (edb *EntriesDatabase) insertCertificate(cert *x509.Certificate) (*gorp.Transaction, uint64, error) {
	//
	// Find the Certificate's issuing CA, using a loop since this is contentious.
	// Also, this is lame. TODO: Be smarter with insertion mutexes
	//

	var issuerID int
	authorityKeyId := base64.StdEncoding.EncodeToString(cert.AuthorityKeyId)
	edb.IssuersLock.RLock()
	issuerID, issuerIsInMap := edb.KnownIssuers[authorityKeyId]
	edb.IssuersLock.RUnlock()

	if !issuerIsInMap {
		// Select until we find it, as there may be contention.
		for {
			// Try to find a matching one first
			err := edb.DbMap.SelectOne(&issuerID, "SELECT issuerID FROM issuer WHERE authorityKeyID = ?", authorityKeyId)
			if err != nil {
				//
				// This is a new issuer, so let's add it to the database
				//
				issuerObj := &Issuer{
					AuthorityKeyId: authorityKeyId,
					CommonName:     cert.Issuer.CommonName,
				}
				err = edb.DbMap.Insert(issuerObj)
				if err == nil {
					issuerID = issuerObj.IssuerID
					// It worked! Proceed.
					break
				}
				log.Printf("Collision on issuer %v, retrying", issuerObj)
			} else {
				break
			}
		}

		if issuerID == 0 {
			// Can't continue, so abort
			return nil, 0, fmt.Errorf("Failed to obtain an issuerID for aki=%s", authorityKeyId)
		}

		// Cache for the future
		edb.IssuersLock.Lock()
		edb.KnownIssuers[authorityKeyId] = issuerID
		edb.IssuersLock.Unlock()
	}

	//
	// Find/insert the Certificate from/into the DB
	//

	txn, err := edb.DbMap.Begin()
	if err != nil {
		return nil, 0, err
	}

	var certId uint64

	// Parse the serial number
	serialNum := fmt.Sprintf("%036x", cert.SerialNumber)

	err = txn.SelectOne(&certId, "SELECT certID FROM certificate WHERE serial = ? AND issuerID = ?", serialNum, issuerID)
	if err != nil {
		//
		// This is a new certificate, so we need to add it to the certificate DB
		// as well as pull out its metadata
		//

		if edb.Verbose {
			fmt.Println(fmt.Sprintf("Processing %s %#v", serialNum, cert.Subject.CommonName))
		}

		certObj := &Certificate{
			Serial:    serialNum,
			IssuerID:  issuerID,
			Subject:   cert.Subject.CommonName,
			NotBefore: cert.NotBefore.UTC(),
			NotAfter:  cert.NotAfter.UTC(),
		}
		err = txn.Insert(certObj)
		if err != nil {
			return txn, 0, fmt.Errorf("DB error on cert insertion: %#v: %s", certObj, err)
		}

		certId = certObj.CertID

		if certId == 0 {
			// Can't continue, so abort
			return txn, 0, fmt.Errorf("Failed to obtain a certId for certificate serial=%s obj=%+v", serialNum, certObj)
		}
	}

	if certId == 0 {
		// CertID was not located
		return txn, 0, fmt.Errorf("Failed to locate a certId for certificate serial=%s", serialNum)
	}

	//
	// Insert the raw certificate, if not already there
	//
	if edb.FullCerts != nil {
		err := edb.FullCerts.Store(certId, cert.Raw)
		if err != nil {
			log.Printf("DB error on raw certificate: %d: %s", certId, err)
		}
	}

	//
	// Process the DNS Names in the Certificate
	//

	// De-dupe the CN and the SAN
	names := make(map[string]struct{})
	if cert.Subject.CommonName != "" {
		names[cert.Subject.CommonName] = struct{}{}
	}
	for _, name := range cert.DNSNames {
		names[name] = struct{}{}
	}

	// Loop and insert names into the DB
	for name, _ := range names {
		nameObj := &SubjectName{
			Name:   name,
			CertID: certId,
		}
		// Ignore errors on insert
		_ = txn.Insert(nameObj)
	}

	err = edb.insertRegisteredDomains(txn, certId, names)
	if err != nil {
		log.Printf("DB error on certId %d registered domains: %#v: %s", certId, names, err)
	}

	return txn, certId, err
}

func (edb *EntriesDatabase) insertRegisteredDomains(txn *gorp.Transaction, certId uint64, names map[string]struct{}) error {
	domains := make(map[string]struct{})
	for name, _ := range names {
		domain, err := publicsuffix.EffectiveTLDPlusOne(name)
		if err != nil {
			// This is non-critical. We'd rather have the cert with an incomplete
			// eTLD, so mask this error
			if edb.Verbose {
				fmt.Printf("%s\n", err)
			}
			continue
		}
		domains[domain] = struct{}{}
	}
	for domain, _ := range domains {
		etld, _ := publicsuffix.PublicSuffix(domain)
		label := strings.Replace(domain, "."+etld, "", 1)
		domainObj := &RegisteredDomain{
			CertID: certId,
			Domain: domain,
			ETLD:   etld,
			Label:  label,
		}
		// Ignore errors on insert
		_ = txn.Insert(domainObj)
	}
	return nil
}

func (edb *EntriesDatabase) InsertCensysEntry(entry *censysdata.CensysEntry) error {
	cert, err := x509.ParseCertificate(entry.CertBytes)
	if err != nil {
		return err
	}

	txn, certId, err := edb.insertCertificate(cert)
	if err != nil {
		if txn != nil {
			txn.Rollback()
		}
		return err
	}

	//
	// Insert the appropriate CensysEntry
	//
	certEntry := &CensysEntry{
		CertID:    certId,
		EntryTime: *entry.Timestamp,
	}
	// Ignore errors on insertion for Censys entry markers
	err = txn.Insert(certEntry)
	if errorIsNotDuplicate(err) {
		return err
	}

	err = txn.Commit()
	return err
}

func (edb *EntriesDatabase) InsertCTEntry(entry *ct.LogEntry) error {
	var cert *x509.Certificate
	var err error

	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err = x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry)
	case ct.PrecertLogEntryType:
		cert, err = x509.ParseTBSCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
	}

	if err != nil {
		return err
	}

	// Skip unimportant entries, if configured
	if edb.IssuerFilter != nil && !strings.HasPrefix(cert.Issuer.CommonName, *edb.IssuerFilter) {
		return nil
	}

	backoff := &backoff.Backoff{
		Jitter: true,
	}

	for count := 0; count < 10; count++ {
		txn, certId, err := edb.insertCertificate(cert)
		if err != nil {
			if txn != nil {
				txn.Rollback()
			}
			log.Printf("Insertion error (#%d): %s", err)
			time.Sleep(backoff.Duration())
			continue
		}

		//
		// Insert the appropriate CertificateLogEntry, ignoring errors if there was a collision
		//

		certLogEntry := &CertificateLogEntry{
			CertID:    certId,
			LogID:     edb.LogId,
			EntryID:   uint64(entry.Index),
			EntryTime: Uint64ToTimestamp(entry.Leaf.TimestampedEntry.Timestamp),
		}
		err = txn.Insert(certLogEntry)
		if errorIsNotDuplicate(err) {
			log.Printf("Non-fatal DB error on cert log entry: %#v: %s", certLogEntry, err)
		}

		return txn.Commit()
	}
	return err
}

func (edb *EntriesDatabase) InsertResolvedName(nameId uint64, address string) error {
	obj := &ResolvedName{
		NameID:  nameId,
		Time:    time.Now(),
		Address: address,
	}
	return edb.DbMap.Insert(obj)
}

func (edb *EntriesDatabase) InsertResolvedPlace(nameId uint64, city string, country string, continent string) error {
	obj := &ResolvedPlace{
		NameID:    nameId,
		Time:      time.Now(),
		City:      city,
		Country:   country,
		Continent: continent,
	}
	return edb.DbMap.Insert(obj)
}
