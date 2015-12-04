package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

var (
	inputPath  = flag.String("i", "", "file path to Certificate Transparency log file")
	offsetFlag = flag.Int64("offset", 0, "byte offset to begin at for search of next valid entry")
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("")
	entryFilePath := *inputPath
	f, err := os.Open(entryFilePath)
	if err != nil {
		log.Fatalf("open: %s", err)
	}
	err = readTo(f, *offsetFlag)
	if err != nil {
		log.Fatalf("unable to find entry: %s", err)
	}
}

func readTo(f *os.File, offset int64) error {
	var total int64
	var zLen int64
	for {
		if err := binary.Read(f, binary.LittleEndian, &zLen); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		zLen = 0
		if _, err := f.Seek(int64(zLen), 1); err != nil {
			return err
		}
		total += zLen
		if total >= offset {
			fmt.Println("first entry after byte offset %d is at offset %d", offset, total)
			return nil
		}
	}
	return fmt.Errorf("byte offset %d was after any valid entry, last entry was at %d", offset, total-zLen)
}
