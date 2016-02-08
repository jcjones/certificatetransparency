This tool imports one CT log at a time into a MySQL database for ease of querying.

It can be used with multiple CT logs by changing the `-log` flag. It defaults to Certly.

Quick Start:
```
go get github.com/jcjones/ct-sql

ct-sql -log https://log.certly.io -dbConnect mysql+tcp://root@localhost:3306/ctdb -limit 10000
```
