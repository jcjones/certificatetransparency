
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `firefoxpageloadstls` (
  `date` date,
  `countTLS` int unsigned,
  `countPageloads` int unsigned,
  `timeAdded` datetime,
  PRIMARY KEY (`date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `firefoxpageloadstls`;