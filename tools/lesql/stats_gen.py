#!/usr/local/bin/python

import argparse, sys
import ConfigParser
import datetime

try:
  import MySQLdb
  from MySQLdb.cursors import DictCursor

except:
  print("You must run 'pip install -r requirements.txt'")
  raise

class DataViz(object):
  def __init__(self):
    self.prefix = "letsencrypt"
    self.certLifetime = 90
    pass

  def setPrefix(self, env):
    self.prefix = env

  def setDBParams(self, host, port, user, password, schema):
    self.db = MySQLdb.connect(host=host, port=port, user=user,
      passwd=password, db=schema)

  def activeCertificates(self):
    print("* Active Certificates")

    cur = self.db.cursor()
    cur.execute("""
      SELECT
          DATE(c.notBefore) AS periodStarting, COUNT(1) AS numIssued
      FROM
          `ct`.certificate AS c
      WHERE
          c.notBefore > DATE_SUB(NOW(), INTERVAL 180 DAY)
      GROUP BY DATE(c.notBefore)
      ORDER BY DATE(c.notBefore) ASC;
      """)

    rawdata = {'date':[], 'issuedThatWeek':[]}


    print("      Date\tIssued\tUnexpired\tExpired\trate/min")

    for row in cur.fetchall():
      datestamp = row[0]
      numIssued = int(row[1])

      rawdata['date'].append(datestamp)
      rawdata['issuedThatWeek'].append(numIssued)
      thisOffset = len(rawdata['date'])

      expired = 0
      unexpired = 0
      for i in range(max(0, thisOffset-self.certLifetime), thisOffset):
        unexpired += rawdata['issuedThatWeek'][i]
      for i in range(0, max(0, thisOffset-self.certLifetime)):
        expired += rawdata['issuedThatWeek'][i]

      # If the date is today, use the real time. Otherwise, increment the day to
      # reflect that the data is really for 23:59:59 on the day from the DB.

      now = datetime.datetime.today()
      if now.date() == datestamp:
        printDate = now
        timeElapsed = now - datetime.datetime.combine(now.date(), datetime.time.min)
        minutesElapsed = timeElapsed.total_seconds() / 60

      else:
        printDate = datestamp + datetime.timedelta(1)
        minutesElapsed = 24.0 * 60

      print("{date}\t{numIssued:6}\t{unexpired:9}\t{expired:7}\t{rate:8.3f}".format(
          date=printDate.strftime("%Y-%m-%d"),
          numIssued=numIssued,
          unexpired=unexpired,
          expired=expired,
          rate=numIssued/minutesElapsed
        ))

  def certificatesByDayGetDate(self, dateObj):
    """
    If the date is today, use the real time. Otherwise, increment the day to
    reflect that the data is really for 23:59:59 on the day given from the DB.
    """
    now = datetime.datetime.today()
    if now.date() == dateObj:
      return now
    return dateObj + datetime.timedelta(1)

def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("-v", dest='verbosity', help="Increase verbosity", action='count')
  parser.add_argument("--config", help="Config File", default="stats_gen.conf")

  args = parser.parse_args()

  config = ConfigParser.ConfigParser({"port":"3306"})
  config.read(args.config)

  viz = DataViz()
  viz.setPrefix(
    config.get("dataviz", "prefix")
  )

  viz.setDBParams(
    config.get("db", "host"),
    config.getint("db", "port"),
    config.get("db", "user"),
    config.get("db", "password"),
    config.get("db", "schema")
  )

  viz.activeCertificates()

if __name__ == "__main__":
 main()