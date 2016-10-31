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
)

var (
	config = utils.NewCTConfig()
)

func main() {
	if config.CertPath == nil || len(*config.CertPath) == 0 {
		fmt.Fprintln(os.Stderr, "You must specify a Certificate Path")
		os.Exit(1)
		return
	}

	certFolderDB, err := utils.NewFolderDatabase(*config.CertPath, 0444, *config.CertsPerFolder)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("unable to open Certificate Path: %s: %s", config.CertPath, err))
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
