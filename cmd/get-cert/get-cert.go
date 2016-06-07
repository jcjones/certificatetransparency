/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Based on github.com/jmhodges/certificatetransparency/tools/lecsv

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/jcjones/ct-sql/utils"
	"github.com/vharitonsky/iniflags"
)

var (
	logUrl         = flag.String("log", "", "URL of the CT Log")
	censysPath     = flag.String("censysJson", "", "Path to a Censys.io certificate json dump")
	censysUrl      = flag.String("censysUrl", "", "URL to a Censys.io certificate json dump")
	dbConnect      = flag.String("dbConnect", "", "DB Connection String")
	verbose        = flag.Bool("v", false, "verbose output")
	certPath       = flag.String("certPath", "", "Path under which to store full DER-encoded certificates")
	certsPerFolder = flag.Uint64("certsPerFolder", 16384, "Certificates per folder, when stored")
	offset         = flag.Uint64("offset", 0, "offset from the beginning")
	offsetByte     = flag.Uint64("offsetByte", 0, "byte offset from the beginning, only for censysJson and not compatible with offset")
	limit          = flag.Uint64("limit", 0, "limit processing to this many entries")
)

func main() {
	flag.Set("allowUnknownFlags", "true")
	iniflags.Parse()

	if certPath == nil || len(*certPath) == 0 {
		fmt.Fprintln(os.Stderr, "You must specify a Certificate Path")
		os.Exit(1)
		return
	}

	certFolderDB, err := utils.NewFolderDatabase(*certPath, 0444, *certsPerFolder)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("unable to open Certificate Path: %s: %s", certPath, err))
		os.Exit(1)
		return
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Must specify the certificate ID to retrieve")
		os.Exit(1)
		return
	}

	id, err := strconv.ParseUint(flag.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("unable to parse as integer: %s", err))
		os.Exit(1)
		return
	}

	data, err := certFolderDB.Get(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("unable to find CertID: %s", err))
		os.Exit(1)
		return
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("unable to write out CertID: %s", err))
		os.Exit(1)
		return
	}

}
