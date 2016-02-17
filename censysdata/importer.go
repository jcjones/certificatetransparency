/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Reads Certificate JSON files from https://censys.io/data/certificates

package censysdata

import (
  "bufio"
  "encoding/base64"
  "encoding/json"
  "time"
  "fmt"
  "os"
)

type CensysEntry struct {
  Valid_nss            bool
  Raw                  string
  Validation_timestamp *string
  Timestamp            *time.Time
  CertBytes            []byte
  LineNumber           uint64
  Offset               uint64
  // parsed    ParsedCensysEntry
}

type Importer struct {
  currentLine   uint64
  currentOffset uint64
  scanner       *bufio.Scanner
  fileHandle    *os.File
}

func (imp *Importer) OpenFile(path string) error {
  imp.currentLine = 0
  fileHandle, err := os.Open(path)
  imp.fileHandle = fileHandle
  imp.scanner = bufio.NewScanner(imp.fileHandle)
  return err
}

func (imp *Importer) Close() error {
  return imp.fileHandle.Close()
}

func (imp *Importer) SeekLine(lineOffset uint64) error {
  for startLine := imp.currentLine; imp.currentLine < lineOffset; imp.currentLine++ {
    ok := imp.scanner.Scan()
    if !ok {
      err := imp.scanner.Err()
      if err != nil {
        return fmt.Errorf("End of file at line %d while seeking forward %d lines from %d", imp.currentLine, lineOffset, startLine)
      }
    }
    rawBytes := imp.scanner.Bytes()
    imp.currentOffset += uint64(len(rawBytes))
  }
  return nil
}

func (imp *Importer) Size() (uint64, error) {
  info, err := imp.fileHandle.Stat()
  if err != nil {
    return 0, err
  }
  return uint64(info.Size()), err
}

func (imp *Importer) NextEntry() (*CensysEntry, error) {
  ok := imp.scanner.Scan()
  if !ok {
    return nil, imp.scanner.Err()
  }
  rawBytes := imp.scanner.Bytes()

  data := &CensysEntry{}
  err := json.Unmarshal(rawBytes, &data)

  certBytes, err := base64.StdEncoding.DecodeString(data.Raw)
  if err != nil {
    return nil, err
  }

  data.CertBytes = certBytes
  data.LineNumber = imp.currentLine
  data.Offset = imp.currentOffset
  data.Timestamp = &time.Time{}

  if data.Validation_timestamp != nil {
    timestamp, err := time.Parse("2006-01-02 15:04:05", *data.Validation_timestamp)
    if err != nil {
      return nil, err
    }
    data.Timestamp = &timestamp
  }

  imp.currentOffset += uint64(len(rawBytes))
  return data, err
}