#!/bin/bash

CERTLOG=~/certificate-transparency-log-certly
SQL="mysql+tcp://root@localhost:3306/ct"

go install github.com/jcjones/certificatetransparency/tools/certlyct-sync
go install github.com/jcjones/certificatetransparency/tools/lesql

echo "Updating CT Log...."
${GOPATH}/bin/certlyct-sync ${CERTLOG}

echo "Exporting CT Log data into MySQL..."
${GOPATH}/bin/lesql -i ${CERTLOG} -dbConnect ${SQL}

echo "Done."
