
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE `netscanqueue` (
  `nameID` bigint(20) unsigned DEFAULT NULL,
  `time` datetime DEFAULT NULL,
  PRIMARY KEY (`nameID`),
  CONSTRAINT `netscanqueue-nameID` FOREIGN KEY (`nameID`) REFERENCES `fqdn` (`nameID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO netscanqueue
  SELECT f.nameID, now() FROM fqdn AS f
    NATURAL LEFT JOIN resolvedname AS r
    WHERE r.time IS NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `netscanqueue`;