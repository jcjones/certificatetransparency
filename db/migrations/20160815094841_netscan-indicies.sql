
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `ctdb`.`resolvedname`
  ADD INDEX `timeIdx` (`time` ASC);
ALTER TABLE `ctdb`.`resolvedname`
  ADD UNIQUE INDEX `name-time-ip-unique` (`nameID` ASC, `time` ASC, `ipaddr` ASC);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `ctdb`.`resolvedname`
  DROP INDEX `timeIdx` ;

ALTER TABLE `ctdb`.`resolvedname`
  DROP INDEX `name-time-ip-unique` ;
