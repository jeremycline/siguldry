-- Add migration script here
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS "key_types" (
    "type" TEXT NOT NULL PRIMARY KEY
);
INSERT INTO key_types(type) VALUES ("RSA");
INSERT INTO key_types(type) VALUES ("ECC");

CREATE TABLE IF NOT EXISTS "key_locations" (
    location TEXT NOT NULL PRIMARY KEY
);
-- Accessible via PKCS11
INSERT INTO key_locations(location) VALUES ("PKCS11");
-- Managed by GPG
INSERT INTO key_locations(location) VALUES ("GPG");

CREATE TABLE IF NOT EXISTS "keys" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "key_type" TEXT NOT NULL,
    "key_location" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL UNIQUE,
    FOREIGN KEY(key_type) REFERENCES key_types(type),
    FOREIGN KEY(key_location) REFERENCES key_locations(location)
);

CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "admin" BOOLEAN NOT NULL
);

CREATE TABLE key_accesses (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "key_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "encrypted_passphrase" BLOB NOT NULL,
    "key_admin" BOOLEAN NOT NULL,
    FOREIGN KEY(key_id) REFERENCES keys(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Both these should be pointless as this is the initial migration.
PRAGMA integrity_check;
PRAGMA foreign_key_check;
