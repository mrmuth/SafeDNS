CREATE TABLE `referers` (
`domain` varchar(255) NOT NULL,
`access_date` date NOT NULL,
`hit_count` int NOT NULL,
PRIMARY KEY (`domain`),
KEY (`access_date`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

alter table referers
add key (domain, access_date);

INSERT INTO referers (domain, access_date, hit_count) 
VALUES ('$domain', '$access_date', 1)
  ON DUPLICATE KEY UPDATE hit_count=hit_count+1;

create procedure statistics.increment_count 
(IN domain_name varchar(255))
INSERT INTO referers (domain, access_date, hit_count)
VALUES (domain_name, curdate(), 1)
  ON DUPLICATE KEY UPDATE hit_count=hit_count+1;

