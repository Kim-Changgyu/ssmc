DROP TABLE IF EXISTS authorities CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users
(
    username    VARCHAR(20) NOT NULL,
    password    VARCHAR(80) NOT NULL,
    enabled     BOOLEAN     NOT NULL  DEFAULT false,
    PRIMARY KEY (username)
);

CREATE TABLE authorities
(
    username    VARCHAR(20) NOT NULL,
    authority   VARCHAR(20) NOT NULL,
    primary key (username)
);