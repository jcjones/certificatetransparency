
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `ctdb`.`certificate` DROP INDEX `SerialIdx`;
ALTER TABLE `ctdb`.`certificate` DROP INDEX `IssuerIdx`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `ctdb`.`certificate` ADD INDEX `SerialIdx` (`serial`);
ALTER TABLE `ctdb`.`certificate` ADD INDEX `IssuerIdx` (`issuerID`);
