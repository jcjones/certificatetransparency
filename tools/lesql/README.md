Scrapes Let's Encrypt certificates from CT into a MySQL database for querying.

See `update_ct_mysql.sh` for an example of how to execute.

Does not copy the ASN.1 encoded certificate into the DB; one can always
obtain it from Boulder given the serial number.