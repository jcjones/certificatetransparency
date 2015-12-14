package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

func main() {
	log.SetPrefix("")
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Printf("usage: knowncagen CA_LIST_FILE")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("unable to open file %#v: %s", os.Args[1], err)
	}
	sc := bufio.NewScanner(f)
	cas := []string{}

	for sc.Scan() {
		ca := strings.Split(sc.Text(), "\t")[0]
		if ca == "" {
			continue
		}
		cas = append(cas, ca)
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}
	sort.Strings(cas)
	last := ""
	fmt.Println("map[string]bool {")
	for _, ca := range cas {
		if ca == last {
			continue
		}
		fmt.Printf("\t%#v: true,\n", ca)
		last = ca
	}
	fmt.Println("}")
}
