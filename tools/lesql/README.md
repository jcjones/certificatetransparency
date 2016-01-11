Scrapes Let's Encrypt certificates from CT into a MySQL database for querying.

Used in https://github.com/jcjones/letsencrypt_statistics

Does not copy the ASN.1 encoded certificate into the DB; one can always
obtain it from Boulder given the serial number.