
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `unexpired_certificate`
  CHANGE COLUMN `notBefore` `notBefore` DATE NULL DEFAULT NULL,
  CHANGE COLUMN `notAfter` `notAfter` DATE NULL DEFAULT NULL;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `unexpired_certificate`
  CHANGE COLUMN `notBefore` `notBefore` DATETIME NULL DEFAULT NULL ,
  CHANGE COLUMN `notAfter` `notAfter` DATETIME NULL DEFAULT NULL ;
