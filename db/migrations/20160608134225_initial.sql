
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `certificate` (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `fqdn` (
  `nameID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`nameID`),
  UNIQUE KEY `NameIdx` (`name`) USING HASH
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `issuer` (
  `issuerID` int(11) NOT NULL AUTO_INCREMENT,
  `commonName` varchar(255) DEFAULT NULL,
  `authorityKeyID` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`issuerID`),
  UNIQUE KEY `authorityKeyID` (`authorityKeyID`),
  KEY `CNIdx` (`commonName`) USING HASH,
  KEY `AKIIdx` (`authorityKeyID`) USING HASH
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `registereddomain` (
  `regdomID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `etld` varchar(255) DEFAULT NULL,
  `label` varchar(255) DEFAULT NULL,
  `domain` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`regdomID`),
  UNIQUE KEY `domain` (`domain`),
  KEY `LabelIdx` (`label`) USING HASH
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `cert_fqdn` (
  `certID` bigint(20) unsigned NOT NULL,
  `nameID` bigint(20) unsigned NOT NULL,
  UNIQUE KEY `composite` (`certID`,`nameID`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `NameIDIdx` (`nameID`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `cert_registereddomain` (
  `certID` bigint(20) unsigned NOT NULL,
  `regdomID` bigint(20) unsigned NOT NULL,
  UNIQUE KEY `composite` (`certID`,`regdomID`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `RegdomIDIdx` (`regdomID`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ctlog` (
  `logID` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`logID`),
  UNIQUE KEY `url` (`url`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `censysentry` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `entryTime` datetime DEFAULT NULL,
  UNIQUE KEY `certID` (`certID`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  CONSTRAINT `censysentry-certID` FOREIGN KEY (`certID`) REFERENCES `certificate` (`certID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ctlogentry` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `logID` int(11) DEFAULT NULL,
  `entryID` bigint(20) unsigned DEFAULT NULL,
  `entryTime` datetime DEFAULT NULL,
  UNIQUE KEY `logID` (`logID`,`entryID`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  CONSTRAINT `logentry-certID` FOREIGN KEY (`certID`) REFERENCES `certificate` (`certID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `resolvedname` (
  `nameID` bigint(20) unsigned DEFAULT NULL,
  `time` datetime DEFAULT NULL,
  `ipaddr` varchar(255) DEFAULT NULL,
  UNIQUE KEY `name-ip` (`nameID`,`ipaddr`),
  KEY `NameIDIdx` (`nameID`) USING BTREE,
  CONSTRAINT `resolvedname-nameID` FOREIGN KEY (`nameID`) REFERENCES `fqdn` (`nameID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `resolvedplace` (
  `nameID` bigint(20) unsigned NOT NULL,
  `time` datetime DEFAULT NULL,
  `city` varchar(255) DEFAULT NULL,
  `country` varchar(255) DEFAULT NULL,
  `continent` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`nameID`),
  KEY `NameIDIdx` (`nameID`) USING BTREE,
  KEY `CountryIdx` (`country`) USING HASH,
  CONSTRAINT `resolvedplace-nameID` FOREIGN KEY (`nameID`) REFERENCES `fqdn` (`nameID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
