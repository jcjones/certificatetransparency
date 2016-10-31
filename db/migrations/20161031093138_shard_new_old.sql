
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

DROP VIEW IF EXISTS `unexpired_certificate`;

CREATE TABLE `unexpired_certificate` (
  `certID` bigint(20) unsigned NOT NULL,
  `issuerID` int(11) DEFAULT NULL,
  `notBefore` datetime DEFAULT NULL,
  `notAfter` datetime DEFAULT NULL,
  PRIMARY KEY (`certID`),
  KEY `notBeforeIdx` (`notBefore`) USING HASH,
  KEY `notAfterIdx` (`notAfter`) USING HASH,
  KEY `issuerIdx` (`issuerID`) USING HASH,
  CONSTRAINT `unexpired-certID` FOREIGN KEY (`certID`) REFERENCES `certificate` (`certID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `unexpired_certificate` SELECT
  `certificate`.`certID` AS `certID`,
  `certificate`.`issuerID` AS `issuerID`,
  `certificate`.`notBefore` AS `notBefore`,
  `certificate`.`notAfter` AS `notAfter`
FROM `certificate` WHERE (now() BETWEEN `certificate`.`notBefore` AND `certificate`.`notAfter`);

ALTER TABLE `ctlog`
  ADD COLUMN `maxEntry` INT(11) NULL AFTER `url`,
  ADD COLUMN `lastEntryTime` DATETIME NULL AFTER `maxEntry`;

UPDATE `ctlog` SET `maxEntry`=(SELECT MAX(`entryID`) FROM `ctlogentry` AS `in` WHERE `logID`=`in`.`logID`), `lastEntryTime`=now();

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `ctlog`
  DROP COLUMN `lastEntryTime`,
  DROP COLUMN `maxEntry`;

DROP TABLE IF EXISTS `unexpired_certificate`;

CREATE VIEW `unexpired_certificate` AS
  select `certificate`.`certID` AS `certID`,
  `certificate`.`serial` AS `serial`,
  `certificate`.`issuerID` AS `issuerID`,
  `certificate`.`subject` AS `subject`,
  `certificate`.`notBefore` AS `notBefore`,
  `certificate`.`notAfter` AS `notAfter`
FROM `certificate` WHERE (now() BETWEEN `certificate`.`notBefore` AND `certificate`.`notAfter`);
