-- Initial database configuration

-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS `censysentry` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `entryTime` datetime DEFAULT NULL,
  UNIQUE KEY `certID` (`certID`),
  KEY `CertIDIdx` (`certID`) USING BTREE
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `certificate` (
  `certID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `serial` varchar(255) DEFAULT NULL,
  `issuerID` int(11) DEFAULT NULL,
  `subject` varchar(255) DEFAULT NULL,
  `notBefore` datetime DEFAULT NULL,
  `notAfter` datetime DEFAULT NULL,
  PRIMARY KEY (`certID`),
  UNIQUE KEY `serial` (`serial`,`issuerID`),
  KEY `SerialIdx` (`serial`) USING HASH,
  KEY `notBeforeIdx` (`notBefore`) USING HASH,
  KEY `notAfterIdx` (`notAfter`) USING HASH,
  KEY `issuerIdx` (`issuerID`) USING HASH
) AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `ctlog` (
  `logID` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`logID`),
  UNIQUE KEY `url` (`url`)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `ctlogentry` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `logID` int(11) DEFAULT NULL,
  `entryID` bigint(20) unsigned DEFAULT NULL,
  `entryTime` datetime DEFAULT NULL,
  UNIQUE KEY `logID` (`logID`,`entryID`),
  KEY `CertIDIdx` (`certID`) USING BTREE
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `issuer` (
  `issuerID` int(11) NOT NULL AUTO_INCREMENT,
  `commonName` varchar(255) DEFAULT NULL,
  `authorityKeyID` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`issuerID`),
  UNIQUE KEY `authorityKeyID` (`authorityKeyID`),
  KEY `CNIdx` (`commonName`) USING HASH,
  KEY `AKIIdx` (`authorityKeyID`) USING HASH
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `name` (
  `nameID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `certID` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`nameID`),
  UNIQUE KEY `certID` (`certID`,`name`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `NameIdx` (`name`) USING HASH
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `registereddomain` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `etld` varchar(255) DEFAULT NULL,
  `label` varchar(255) DEFAULT NULL,
  `domain` varchar(255) DEFAULT NULL,
  UNIQUE KEY `certID` (`certID`,`domain`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `DomainIdx` (`domain`) USING HASH,
  KEY `LabelIdx` (`label`) USING HASH
) DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE `registereddomain`;
DROP TABLE `name`;
DROP TABLE `issuer`;
DROP TABLE `ctlogentry`;
DROP TABLE `ctlog`;
DROP TABLE `certificate`;
DROP TABLE `censysentry`;