-- Add migration script here
PRAGMA foreign_keys = ON;

CREATE TABLE keys (
    id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_location TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE(fingerprint),
    FOREIGN KEY(key_type) REFERENCES key_types(type),
    FOREIGN KEY(key_location) REFERENCES key_location(location),
);

CREATE TABLE key_types (
    type TEXT NOT NULL PRIMARY KEY,
);
INSERT INTO key_types(type) VALUES ("RSA");
INSERT INTO key_types(type) VALUES ("ECC");

CREATE TABLE key_locations (
    location TEXT NOT NULL PRIMARY KEY,
);
-- Accessible via PKCS11
INSERT INTO key_location(location) VALUES ("PKCS11");
-- Managed by GPG
INSERT INTO key_location(location) VALUES ("GPG");

CREATE TABLE users (
    id INTEGER NOT NULL,
    name TEXT NOT NULL,
    admin BOOLEAN NOT NULL,
    UNIQUE(name),
)

CREATE TABLE key_accesses (
    id INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_passphrase BLOB NOT NULL,
    key_admin BOOLEAN NOT NULL,
    FOREIGN KEY(key_id) REFERENCES keys(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
)

-- Both these should be pointless as this is the initial migration.
PRAGMA integrity_check;
PRAGMA foreign_key_check;
