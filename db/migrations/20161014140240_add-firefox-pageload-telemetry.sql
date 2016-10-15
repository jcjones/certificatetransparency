
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `firefoxpageloadstls` (
  `datestamp` date,
  `countTLS` int unsigned,
  `countPageloads` int unsigned,
  `timeAdded` datetime,
  PRIMARY KEY (`datestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `firefoxpageloadstls`;