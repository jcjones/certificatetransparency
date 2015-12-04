package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	inputPath  = flag.String("i", "", "file path to Certificate Transparency log file (required)")
	outputPath = flag.String("o", "", "file path to store index of Certificate Transparency log file (required)")
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("")
	entryFilePath := *inputPath
	if entryFilePath == "" || *outputPath == "" {
		flag.Usage() // FIXME
		os.Exit(2)
	}
	f, err := os.Open(entryFilePath)
	if err != nil {
		log.Fatalf("open: %s", err)
	}
	temp, err := ioutil.TempFile("", "ctindex-")
	if err != nil {
		log.Fatal("unable to create temporary file: %s", err)
	}
	fmt.Println("writing to temp file ", temp.Name())
	b := bufio.NewWriter(temp)
	err = readTo(f, b)
	if err != nil {
		log.Fatalf("unable to find entry: %s", err)
	}
	b.Flush()
	err = os.Rename(temp.Name(), *outputPath)
	if err != nil {
		log.Fatal("unable to move temporary file to %#v: %s", *outputPath, err)
	}
	fmt.Println(*outputPath)
}

func readTo(f *os.File, w io.Writer) error {
	total := uint64(0)
	bs := make([]byte, 4)
	out := make([]byte, 8)
	for {
		if _, err := io.ReadFull(f, bs); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		zLen := binary.LittleEndian.Uint32(bs)
		total += uint64(zLen)
		binary.BigEndian.PutUint64(out, total)
		w.Write(out)
		if _, err := f.Seek(int64(zLen), 1); err != nil {
			return err
		}
	}
	return nil
}
