#!/bin/bash


# sync_and_diff_csv.sh will sync the ct log file with ct-sync and then run lecsv
# on only the new certificates that arrived in that latest ct-sync run. lecsv
# will print the CSV records to stdout and tee them to le_domain_diff.csv.


set -o errexit

ctfile=$1
ctoffset=$2

if [ -z $ctfile ]; then
  echo "usage: sync_and_csv.sh CT_FILE [CT_FILE_BYTE_OFFSET]" > /dev/stderr
  exit 1
fi

if [[ ( -f $ctfile ) && ( -z $ctoffset ) ]]; then
  ctoffset=$(wc -c $ctfile | sed -e 's/^ //' |  cut -d' ' -f 1)
fi

ct-sync $ctfile 1>&2
echo "new Let's Encrypt certificates from after byte offset ${ctoffset}" > /dev/stderr
lecsv -i $ctfile -offset $ctoffset | tee le_domain_diff.csv
