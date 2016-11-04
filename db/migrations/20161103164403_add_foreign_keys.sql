
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `cert_fqdn`
  ADD CONSTRAINT `cert_fqdn-certID` FOREIGN KEY (`certID`) REFERENCES `certificate` (`certID`) ON DELETE CASCADE;

ALTER TABLE `cert_fqdn`
  ADD CONSTRAINT `cert_fqdn-nameID` FOREIGN KEY (`nameID`) REFERENCES `fqdn` (`nameID`) ON DELETE CASCADE;

ALTER TABLE `cert_registereddomain`
  ADD CONSTRAINT `cert_registereddomain-certID` FOREIGN KEY (`certID`) REFERENCES `certificate` (`certID`) ON DELETE CASCADE;

ALTER TABLE `cert_registereddomain`
  ADD CONSTRAINT `cert_registereddomain-regdomID` FOREIGN KEY (`regdomID`) REFERENCES `registereddomain` (`regdomID`) ON DELETE CASCADE;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `cert_fqdn`
  REMOVE CONSTRAINT `cert_fqdn-certID`;

ALTER TABLE `cert_fqdn`
  REMOVE CONSTRAINT `cert_fqdn-nameID`;

ALTER TABLE `cert_registereddomain`
  REMOVE CONSTRAINT `cert_registereddomain-certID`;

ALTER TABLE `cert_registereddomain`
  REMOVE CONSTRAINT `cert_registereddomain-regdomID`;
