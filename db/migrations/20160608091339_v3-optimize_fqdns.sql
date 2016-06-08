-- Optimize the names table to reduce reuse of name IDs

-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE IF NOT EXISTS `cert_fqdn` (
  `certID` bigint(20) unsigned NOT NULL,
  `nameID` bigint(20) unsigned NOT NULL,
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `NameIDIdx` (`nameID`) USING BTREE,
  UNIQUE KEY `composite` (`certID`,`nameID`)
) DEFAULT CHARSET=utf8
  SELECT certID, nameID FROM `ctdb`.`name`;

ALTER TABLE `ctdb`.`resolvedplace` DROP FOREIGN KEY `resolvedplace-nameID`;
ALTER TABLE `ctdb`.`resolvedname` DROP FOREIGN KEY `resolvedname-nameID`;

CREATE TABLE `fqdn` (
  `nameID` bigint(20) unsigned NOT NULL,
  `name` varchar(255) NOT NULL,
  UNIQUE KEY `NameIdx` (`name`) USING HASH,
  PRIMARY KEY (`nameID`)
) DEFAULT CHARSET=utf8
  SELECT DISTINCT nameID, name FROM `ctdb`.`name`;

ALTER TABLE `ctdb`.`resolvedplace`
ADD CONSTRAINT `resolvedplace-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `ctdb`.`fqdn` (`nameID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

ALTER TABLE `ctdb`.`resolvedname`
ADD CONSTRAINT `resolvedname-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `ctdb`.`fqdn` (`nameID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

DROP TABLE `ctdb`.`name`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

CREATE TABLE `name` (
  `nameID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `certID` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  KEY `NameIDIdx` (`nameID`) USING HASH,
  UNIQUE KEY `certID` (`certID`,`name`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `NameIdx` (`name`) USING HASH,
  CONSTRAINT `name-certID` FOREIGN KEY (`certID`) REFERENCES `certificate` (`certID`) ON DELETE CASCADE
) DEFAULT CHARSET=utf8
  SELECT DISTINCT nameID, certID, name FROM `ctdb`.`cert_fqdn` NATURAL JOIN `ctdb`.`fqdn`;

ALTER TABLE `ctdb`.`resolvedplace` DROP FOREIGN KEY `resolvedplace-nameID`;
ALTER TABLE `ctdb`.`resolvedname` DROP FOREIGN KEY `resolvedname-nameID`;

ALTER TABLE `ctdb`.`resolvedplace`
ADD CONSTRAINT `resolvedplace-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `ctdb`.`name` (`nameID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

ALTER TABLE `ctdb`.`resolvedname`
ADD CONSTRAINT `resolvedname-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `ctdb`.`name` (`nameID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

DROP TABLE `ctdb`.`cert_fqdn`;
DROP TABLE `ctdb`.`fqdn`;
