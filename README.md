This tool imports one CT log at a time into a MySQL database for ease of querying.

It can be used with multiple CT logs by changing the `-log` flag.

Quick Start:
```
go get github.com/jcjones/ct-sql/cmd/ct-sql

echo "dbConnect = mysql+tcp://root@localhost:3306/ctdb" > ./ct-sql.ini

ct-sql -config ./ct-sql.ini -log https://log.certly.io -limit 10000
ct-sql -config ./ct-sql.ini -censysUrl https://url_to_censys/path/certificates.json
```
