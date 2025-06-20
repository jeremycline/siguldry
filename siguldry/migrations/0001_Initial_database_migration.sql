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
    "name" TEXT NOT NULL UNIQUE,
    "key_type" TEXT NOT NULL,
    "key_location" TEXT NOT NULL,
    -- This uniquely identifies a key and its value is dependant on `key_location`; it may
    -- be a PKCS11 URI or a GPG fingerprint, for example.
    "handle" TEXT NOT NULL UNIQUE,
    FOREIGN KEY(key_type) REFERENCES key_types(type) ON DELETE RESTRICT,
    FOREIGN KEY(key_location) REFERENCES key_locations(location) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL UNIQUE,
    "admin" BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS "key_accesses" (
    "id" INTEGER NOT NULL PRIMARY KEY,
    "key_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,
    "encrypted_passphrase" BLOB NOT NULL,
    "key_admin" BOOLEAN NOT NULL,
    -- Foreign key constraints that require all key_accesses referencing a user or key
    -- to be explicitly removed before a key or user can be deleted.
    FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE RESTRICT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
);

-- Both these should be pointless as this is the initial migration.
PRAGMA integrity_check;
PRAGMA foreign_key_check;
