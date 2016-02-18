/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Reads Certificate JSON files from https://censys.io/data/certificates

package censysdata

import (
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io"
  "log"
  "os"
  "time"
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
  byteCounter   *ImporterByteCounter
  decoder       *json.Decoder
  fileHandle    *os.File
}

type ImporterByteCounter struct {
  CurrentOffset uint64
}

func (ibc *ImporterByteCounter) Write(p []byte) (n int, err error) {
  ibc.CurrentOffset += uint64(len(p))
  return 0, nil
}

func (imp *Importer) OpenFile(path string) error {
  imp.currentLine = 0
  fileHandle, err := os.Open(path)
  imp.fileHandle = fileHandle
  imp.byteCounter = &ImporterByteCounter{}
  readerObj := io.TeeReader(imp.fileHandle, imp.byteCounter)
  imp.decoder = json.NewDecoder(readerObj)
  return err
}

func (imp *Importer) Close() error {
  return imp.fileHandle.Close()
}

func (imp *Importer) SeekLine(lineOffset uint64) error {
  for ; imp.currentLine < lineOffset; imp.currentLine++ {
    obj, err := imp.NextEntry()

    if err != nil {
      return err
    }
    if obj == nil {
      return fmt.Errorf("Unexpected EOF")
    }
  }
  log.Printf("Skipped to line %d, offset %d", imp.currentLine, imp.byteCounter.CurrentOffset)
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
  if !imp.decoder.More() {
    return nil, nil
  }

  data := &CensysEntry{}
  err := imp.decoder.Decode(&data)
  if err != nil {
    return nil, err
  }

  certBytes, err := base64.StdEncoding.DecodeString(data.Raw)
  if err != nil {
    return nil, err
  }

  data.CertBytes = certBytes
  data.LineNumber = imp.currentLine
  data.Offset = imp.byteCounter.CurrentOffset
  data.Timestamp = &time.Time{}

  if data.Validation_timestamp != nil {
    timestamp, err := time.Parse("2006-01-02 15:04:05", *data.Validation_timestamp)
    if err != nil {
      return nil, err
    }
    data.Timestamp = &timestamp
  }

  return data, err
}