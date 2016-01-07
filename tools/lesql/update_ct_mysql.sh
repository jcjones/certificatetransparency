#!/bin/bash

CERTLOG=~/certificate-transparency-log-certly
SQL="mysql+tcp://root@localhost:3306/ct"

go install github.com/jcjones/certificatetransparency/tools/lesql

echo "Exporting CT Log data into MySQL..."
${GOPATH}/bin/lesql -i ${CERTLOG} -dbConnect ${SQL}

echo "Done."
