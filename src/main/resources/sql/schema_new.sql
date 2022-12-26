DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS group_permission CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE permissions
(
    id          BIGINT      NOT NULL,
    name        VARCHAR(20) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE groups
(
    id          BIGINT      NOT NULL,
    name        VARCHAR(20) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE group_permission
(
    id              BIGINT  NOT NULL,
    group_id        BIGINT  NOT NULL,
    permission_id   BIGINT  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT unq_group_id_permission_id UNIQUE (group_id, permission_id),
    CONSTRAINT fk_group_id_for_group_permission FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_permission_id_for_group_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE users
(
    id              BIGINT          NOT NULL AUTO_INCREMENT,
    username        VARCHAR(20)     NOT NULL,
    provider        VARCHAR(20)     NOT NULL,
    provider_id     VARCHAR(80)     NOT NULL,
    profile_image   VARCHAR(255)    NOT NULL,
    group_id        BIGINT          NOT NULL,
    primary key (id),
    CONSTRAINT unq_username UNIQUE (username),
    CONSTRAINT unq_provider_and_id UNIQUE (provider, provider_id),
    CONSTRAINT fk_group_id_for_user FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE RESTRICT ON UPDATE RESTRICT
);