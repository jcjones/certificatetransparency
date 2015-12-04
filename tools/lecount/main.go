package main

import (
	"crypto/x509"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/agl/certificatetransparency"
)

var (
	inputPath  = flag.String("i", "", "file path to Certificate Transparency log file")
	offsetFlag = flag.Int64("offset", 0, "byte offset to skip to in the file")
	verbose    = flag.Bool("v", false, "verbose output")
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("")
	entryFilePath := *inputPath
	offset := *offsetFlag
	if len(entryFilePath) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	f, err := os.Open(entryFilePath)
	if err != nil {
		log.Fatalf("unable to open %#v: %s", entryFilePath, err)
	}
	if *verbose {
		log.Printf("seeking to %d", offset)
	}
	_, err = f.Seek(offset, 0)
	if err != nil {
		log.Fatalf("unable to seek to %d in %#v: %s", offset, entryFilePath, err)
	}
	if *verbose {
		log.Printf("finished seeking")
	}
	ef := certificatetransparency.EntriesFile{f}
	outputLock := &sync.Mutex{}
	w := csv.NewWriter(os.Stdout)

	err = ef.Map(func(ep *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			return
		}
		cert, err := x509.ParseCertificate(ep.Entry.X509Cert)
		if err != nil {
			return
		}
		if !strings.HasPrefix(cert.Issuer.CommonName, "Let's Encrypt Authority") {
			if *verbose {
				fmt.Fprintf(os.Stderr, "skipping (index %d, offset %d) %#v\n", ep.Index, offset+ep.Offset, cert.Issuer.CommonName)
			}
			return
		}

		// De-dupe just in case.
		names := make(map[string]struct{})
		if cert.Subject.CommonName != "" {
			names[cert.Subject.CommonName] = struct{}{}
		}
		for _, name := range cert.DNSNames {
			names[name] = struct{}{}
		}
		records := make([][]string, 0, len(names))
		for name, _ := range names {
			r := makeCSVRecord(name, ep.Entry, cert)
			records = append(records, r)
		}
		outputLock.Lock()
		err = w.WriteAll(records)
		outputLock.Unlock()
		if err != nil {
			return
		}
	})
	if err != nil {
		log.Fatalf("error while searching CT entries file: %s", err)
	}
}

func makeCSVRecord(name string, ep *certificatetransparency.Entry, cert *x509.Certificate) []string {
	return []string{
		name,
		cert.SerialNumber.String(),
		strconv.FormatInt(cert.NotBefore.UTC().Unix(), 10),
		strconv.FormatInt(ep.Time.UTC().Unix(), 10),
	}
}
