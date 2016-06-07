/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"flag"
	"github.com/vharitonsky/iniflags"
)

type CTConfig struct {
	LogUrl         *string
	CensysPath     *string
	CensysUrl      *string
	DbConnect      *string
	Verbose        *bool
	CertPath       *string
	CertsPerFolder *uint64
	Offset         *uint64
	OffsetByte     *uint64
	Limit          *uint64
	GeoipDbPath    *string
}

func NewCTConfig() *CTConfig {
	ret := &CTConfig{
		LogUrl:         flag.String("log", "", "URL of the CT Log"),
		CensysPath:     flag.String("censysJson", "", "Path to a Censys.io certificate json dump"),
		CensysUrl:      flag.String("censysUrl", "", "URL to a Censys.io certificate json dump"),
		DbConnect:      flag.String("dbConnect", "", "DB Connection String"),
		Verbose:        flag.Bool("v", false, "verbose output"),
		CertPath:       flag.String("certPath", "", "Path under which to store full DER-encoded certificates"),
		CertsPerFolder: flag.Uint64("certsPerFolder", 16384, "Certificates per folder, when stored"),
		Offset:         flag.Uint64("offset", 0, "offset from the beginning"),
		OffsetByte:     flag.Uint64("offsetByte", 0, "byte offset from the beginning, only for censysJson and not compatible with offset"),
		Limit:          flag.Uint64("limit", 0, "limit processing to this many entries"),
		GeoipDbPath:    flag.String("geoipDbPath", "", "Path to GeoIP2-City.mmdb"),
	}

	iniflags.Parse()
	return ret
}

func (c *CTConfig) Usage() {
	flag.Usage()
}
