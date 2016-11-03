
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `ctdb`.`registereddomain` DROP INDEX `LabelIdx`;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `ctdb`.`registereddomain` ADD INDEX `LabelIdx` (`label`) USING HASH;
