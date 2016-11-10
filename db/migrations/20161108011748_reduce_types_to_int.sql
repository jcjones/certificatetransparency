-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `cert_fqdn`
DROP FOREIGN KEY `cert_fqdn-nameID`,
DROP FOREIGN KEY `cert_fqdn-certID`;
ALTER TABLE `cert_fqdn`
CHANGE COLUMN `certID` `certID` INT UNSIGNED NOT NULL ,
CHANGE COLUMN `nameID` `nameID` INT UNSIGNED NOT NULL ;

ALTER TABLE `cert_registereddomain`
DROP FOREIGN KEY `cert_registereddomain-regdomID`,
DROP FOREIGN KEY `cert_registereddomain-certID`;
ALTER TABLE `cert_registereddomain`
CHANGE COLUMN `certID` `certID` INT UNSIGNED NOT NULL ,
CHANGE COLUMN `regdomID` `regdomID` INT UNSIGNED NOT NULL ;

ALTER TABLE `netscanqueue`
DROP FOREIGN KEY `netscanqueue-nameID`;
ALTER TABLE `netscanqueue`
CHANGE COLUMN `nameID` `nameID` INT UNSIGNED NOT NULL ;

ALTER TABLE `resolvedname`
DROP FOREIGN KEY `resolvedname-nameID`;
ALTER TABLE `resolvedname`
CHANGE COLUMN `nameID` `nameID` INT UNSIGNED NOT NULL ;

ALTER TABLE `resolvedplace`
DROP FOREIGN KEY `resolvedplace-nameID`;
ALTER TABLE `resolvedplace`
CHANGE COLUMN `nameID` `nameID` INT UNSIGNED NOT NULL ;

ALTER TABLE `censysentry`
DROP FOREIGN KEY `censysentry-certID`;
ALTER TABLE `censysentry`
CHANGE COLUMN `certID` `certID` INT UNSIGNED NOT NULL ;

ALTER TABLE `ctlogentry`
DROP FOREIGN KEY `logentry-certID`;
ALTER TABLE `ctlogentry`
CHANGE COLUMN `certID` `certID` INT UNSIGNED NOT NULL ;

ALTER TABLE `unexpired_certificate`
DROP FOREIGN KEY `unexpired-certID`;
ALTER TABLE `unexpired_certificate`
CHANGE COLUMN `certID` `certID` INT UNSIGNED NOT NULL ;

ALTER TABLE `fqdn`
CHANGE COLUMN `nameID` `nameID` INT UNSIGNED NOT NULL AUTO_INCREMENT ;

ALTER TABLE `registereddomain`
CHANGE COLUMN `regdomID` `regdomID` INT UNSIGNED NOT NULL AUTO_INCREMENT ;

ALTER TABLE `certificate`
CHANGE COLUMN `certID` `certID` INT UNSIGNED NOT NULL AUTO_INCREMENT ;


ALTER TABLE `cert_fqdn`
ADD CONSTRAINT `cert_fqdn-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `fqdn` (`nameID`)
  ON DELETE CASCADE,
ADD CONSTRAINT `cert_fqdn-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `certificate` (`certID`)
  ON DELETE CASCADE;

ALTER TABLE `cert_registereddomain`
ADD CONSTRAINT `cert_registereddomain-regdomID`
  FOREIGN KEY (`regdomID`)
  REFERENCES `registereddomain` (`regdomID`)
  ON DELETE CASCADE,
ADD CONSTRAINT `cert_registereddomain-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `certificate` (`certID`)
  ON DELETE CASCADE;

ALTER TABLE `netscanqueue`
ADD CONSTRAINT `netscanqueue-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `fqdn` (`nameID`)
  ON DELETE CASCADE;

ALTER TABLE `resolvedname`
ADD CONSTRAINT `resolvedname-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `fqdn` (`nameID`)
  ON DELETE CASCADE;

ALTER TABLE `resolvedplace`
ADD CONSTRAINT `resolvedplace-nameID`
  FOREIGN KEY (`nameID`)
  REFERENCES `fqdn` (`nameID`)
  ON DELETE CASCADE;

ALTER TABLE `censysentry`
ADD CONSTRAINT `censysentry-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `certificate` (`certID`)
  ON DELETE CASCADE;

ALTER TABLE `ctlogentry`
ADD CONSTRAINT `logentry-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `certificate` (`certID`)
  ON DELETE CASCADE;

ALTER TABLE `unexpired_certificate`
ADD CONSTRAINT `unexpired-certID`
  FOREIGN KEY (`certID`)
  REFERENCES `certificate` (`certID`)
  ON DELETE CASCADE;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

