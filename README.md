This tool imports one CT log at a time into a MySQL database for ease of querying.

It can be used with multiple CT logs by changing the `-log` flag.

Quick Start:
```
# Acquire CT data
go get github.com/jcjones/ct-sql/cmd/ct-sql

# Configure ct-sql
echo "dbConnect = mysql+tcp://root@localhost:3306/ctdb" > ./ct-sql.ini

# Prepare the Database (using Goose migration took)
go get bitbucket.org/liamstask/goose/cmd/goose

pushd $GOPATH/src/github.com/jcjones/ct-sql
cat db/dbconf.yml
# Edit dbconf.yml as needed for user/pass
goose up
goose status
popd

# Scan a CT log
ct-sql -config ./ct-sql.ini -log https://log.certly.io -limit 10000

# Scan a Censys.io Export
ct-sql -config ./ct-sql.ini -censysUrl https://url_to_censys/path/certificates.json

# Resolve sites to determine their server locations
go get github.com/jcjones/ct-sql/cmd/ct-sql-netscan
ct-sql-netscan -config ./ct-sql.ini -limit 10
```

## Vendored Packages
We're using `[godep](https://github.com/tools/godep)` to handle vendored dependencies.
```godep save ./cmd/ct-sql/ ./cmd/ct-sql-netscan/ ./cmd/telemetry-update/ ./cmd/get-cert/```
