ALTER TABLE `ctdb`.`ctlogentry`
ADD CONSTRAINT `logentry-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `ctdb`.`certificate` (`certID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

ALTER TABLE `ctdb`.`censysentry`
ADD CONSTRAINT `censysentry-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `ctdb`.`certificate` (`certID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

ALTER TABLE `ctdb`.`name`
ADD CONSTRAINT `name-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `ctdb`.`certificate` (`certID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

ALTER TABLE `ctdb`.`registereddomain`
ADD CONSTRAINT `registereddomain-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `ctdb`.`certificate` (`certID`)
  ON DELETE CASCADE
  ON UPDATE RESTRICT;

CREATE TABLE `resolvedname` (
  `nameID` bigint(20) unsigned DEFAULT NULL,
  `time` datetime DEFAULT NULL,
  `ipaddr` varchar(255) DEFAULT NULL,
  KEY `NameIDIdx` (`nameID`) USING BTREE,
  CONSTRAINT `resolvedname-nameID` FOREIGN KEY (`nameID`) REFERENCES `name` (`nameID`) ON DELETE CASCADE ON UPDATE RESTRICT
) DEFAULT CHARSET=utf8;

CREATE TABLE `resolvedplace` (
  `nameID` bigint(20) unsigned DEFAULT NULL,
  `time` datetime DEFAULT NULL,
  `city` varchar(255) DEFAULT NULL,
  `country` varchar(255) DEFAULT NULL,
  `continent` varchar(255) DEFAULT NULL,
  KEY `NameIDIdx` (`nameID`) USING BTREE,
  KEY `CountryIdx` (`country`) USING HASH,
  CONSTRAINT `resolvedplace-nameID` FOREIGN KEY (`nameID`) REFERENCES `name` (`nameID`) ON DELETE CASCADE ON UPDATE RESTRICT
) DEFAULT CHARSET=utf8;
