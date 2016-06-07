CREATE TABLE `censysentry` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `entryTime` datetime DEFAULT NULL,
  UNIQUE KEY `certID` (`certID`),
  KEY `CertIDIdx` (`certID`) USING BTREE
) DEFAULT CHARSET=utf8;

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
) AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE `ctlog` (
  `logId` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`logId`),
  UNIQUE KEY `url` (`url`)
) DEFAULT CHARSET=utf8;

CREATE TABLE `ctlogentry` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `logId` int(11) DEFAULT NULL,
  `entryId` bigint(20) unsigned DEFAULT NULL,
  `entryTime` datetime DEFAULT NULL,
  UNIQUE KEY `logId` (`logId`,`entryId`),
  KEY `CertIDIdx` (`certID`) USING BTREE
) DEFAULT CHARSET=utf8;

CREATE TABLE `issuer` (
  `issuerID` int(11) NOT NULL AUTO_INCREMENT,
  `commonName` varchar(255) DEFAULT NULL,
  `authorityKeyId` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`issuerID`),
  UNIQUE KEY `authorityKeyId` (`authorityKeyId`),
  KEY `CNIdx` (`commonName`) USING HASH,
  KEY `AKIIdx` (`authorityKeyId`) USING HASH
) DEFAULT CHARSET=utf8;

CREATE TABLE `name` (
  `nameID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `certID` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`nameID`),
  UNIQUE KEY `certID` (`certID`,`name`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `NameIdx` (`name`) USING HASH
) DEFAULT CHARSET=utf8;

CREATE TABLE `registereddomain` (
  `certID` bigint(20) unsigned DEFAULT NULL,
  `etld` varchar(255) DEFAULT NULL,
  `label` varchar(255) DEFAULT NULL,
  `domain` varchar(255) DEFAULT NULL,
  UNIQUE KEY `certID` (`certID`,`domain`),
  KEY `CertIDIdx` (`certID`) USING BTREE,
  KEY `DomainIdx` (`domain`) USING HASH,
  KEY `LabelIdx` (`label`) USING HASH
) DEFAULT CHARSET=utf8;