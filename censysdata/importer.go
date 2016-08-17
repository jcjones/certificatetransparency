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
	"net/http"
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

type Importer interface {
	SeekByte(byteOffset uint64) error
	Size() (uint64, error)
	SeekLine(lineOffset uint64) error
	NextEntry() (*CensysEntry, error)
	ByteOffset() uint64
	String() string
}

type FileImporter struct {
	currentLine uint64
	byteCounter *ImporterByteCounter
	decoder     *json.Decoder
	fileHandle  *os.File
}

type ImporterByteCounter struct {
	CurrentOffset uint64
}

func (ibc *ImporterByteCounter) Write(p []byte) (n int, err error) {
	ibc.CurrentOffset += uint64(len(p))
	return 0, nil
}

func OpenFileHandle(fileHandle *os.File) (*FileImporter, error) {
	byteCounter := &ImporterByteCounter{}
	readerObj := io.TeeReader(fileHandle, byteCounter)
	importer := &FileImporter{
		currentLine: 0,
		byteCounter: byteCounter,
		decoder:     json.NewDecoder(readerObj),
		fileHandle:  fileHandle,
	}
	return importer, nil
}

func OpenFile(path string) (*FileImporter, error) {
	fileHandle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return OpenFileHandle(fileHandle)
}

func (imp *FileImporter) Close() error {
	return imp.fileHandle.Close()
}

func (imp *FileImporter) String() string {
	return fmt.Sprintf("File Importer (File=%s)", imp.fileHandle.Name())
}

func (imp *FileImporter) SeekByte(byteOffset uint64) error {
	newOffset, err := imp.fileHandle.Seek(int64(byteOffset), 1)
	log.Printf("Seeked forward %d bytes, now at %d", byteOffset, newOffset)
	imp.byteCounter.CurrentOffset = uint64(newOffset)
	return err
}

func (imp *FileImporter) Size() (uint64, error) {
	info, err := imp.fileHandle.Stat()
	if err != nil {
		return 0, err
	}
	return uint64(info.Size()), err
}

func (imp *FileImporter) SeekLine(lineOffset uint64) error {
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

func (imp *FileImporter) ByteOffset() uint64 {
	return imp.byteCounter.CurrentOffset
}

func (imp *FileImporter) NextEntry() (*CensysEntry, error) {
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
	data.Offset = imp.ByteOffset()
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

type HttpImporter struct {
	currentLine    uint64
	startingOffset uint64
	byteCounter    *ImporterByteCounter
	decoder        *json.Decoder
	url            string
	resp           *http.Response
}

func OpenURL(url string) (*HttpImporter, error) {
	importer := &HttpImporter{
		currentLine: 0,
		byteCounter: &ImporterByteCounter{},
		url:         url,
		decoder:     nil,
		resp:        nil,
	}
	return importer, nil
}

func (imp *HttpImporter) String() string {
	return fmt.Sprintf("HTTP Importer (URL=%s)", imp.url)
}

func (imp *HttpImporter) ByteOffset() uint64 {
	return imp.byteCounter.CurrentOffset
}

func (imp *HttpImporter) SeekByte(byteOffset uint64) error {
	if imp.resp != nil {
		return fmt.Errorf("Cannot seek on a HTTP session that already started.")
	}

	imp.startingOffset = byteOffset
	imp.byteCounter.CurrentOffset = byteOffset

	log.Printf("Set byte offset to %d", byteOffset)
	return nil
}

func (imp *HttpImporter) Size() (uint64, error) {
	if imp.resp != nil {
		return uint64(imp.resp.ContentLength), nil
	}
	return 0, fmt.Errorf("Cannot get size of an HTTP session that has not started.")
}

func (imp *HttpImporter) SeekLine(lineOffset uint64) error {
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

func (imp *HttpImporter) NextEntry() (*CensysEntry, error) {
	if imp.resp == nil {
		// Not yet connected, so let's lazily connect
		req, err := http.NewRequest("GET", imp.url, nil)
		if err != nil {
			return nil, err
		}

		if imp.startingOffset > 0 {
			req.Header.Add("Range", fmt.Sprintf("bytes=%d-", imp.startingOffset))
		}

		client := &http.Client{}
		imp.resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}

		imp.decoder = json.NewDecoder(io.TeeReader(imp.resp.Body, imp.byteCounter))
	}

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
	data.Offset = imp.ByteOffset()
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
