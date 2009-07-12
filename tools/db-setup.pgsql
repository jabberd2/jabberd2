--
-- This is the required schema for PostgreSQL. Load this into the
-- database using the psql interactive terminal:
--
--     template1=> \i db-setup.pgsql
--

-- CREATE DATABASE jabberd2;
-- \c jabberd2

CREATE SEQUENCE "object-sequence";

--
-- c2s authentication/registration table
--
CREATE TABLE "authreg" (
    "username" varchar(1023) NOT NULL,
    "realm" varchar(1023) NOT NULL,
    "password" varchar(256),
    PRIMARY KEY ("username", "realm") );

CREATE INDEX i_authreg_username ON "authreg"("username");
CREATE INDEX i_authreg_realm ON "authreg"("realm");

--
-- Session manager tables 
--

--
-- Active (seen) users
-- Used by: core
--
CREATE TABLE "active" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "time" integer NOT NULL DEFAULT 0 );

--
-- Logout times
-- Used by: mod_iq_last
--
CREATE TABLE "logout" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "time" integer NOT NULL DEFAULT 0 );

--
-- Roster items
-- Used by: mod_roster
--
CREATE TABLE "roster-items" (
    "collection-owner" text NOT NULL,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "jid" text NOT NULL,
    "name" text,
    "to" boolean NOT NULL,
    "from" boolean NOT NULL,
    "ask" integer NOT NULL,
    PRIMARY KEY ("collection-owner", "jid") );

CREATE INDEX i_rosteri_owner ON "roster-items"("collection-owner");

--
-- Roster groups
-- Used by: mod_roster
--
CREATE TABLE "roster-groups" (
    "collection-owner" text NOT NULL,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "jid" text NOT NULL,
    "group" text NOT NULL,
    PRIMARY KEY ("collection-owner", "jid", "group") );

CREATE INDEX i_rosterg_owner ON "roster-groups"("collection-owner");
CREATE INDEX i_rosterg_owner_jid ON "roster-groups"("collection-owner", "jid");

--
-- vCard (user profile information)
-- Used by: mod_iq_vcard
--
CREATE TABLE "vcard" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "fn" text,
    "nickname" text,
    "url" text,
    "tel" text,
    "email" text,
    "jabberid" text,
    "mailer" text,
    "title" text,
    "role" text,
    "bday" text,
    "tz" text,
    "n-family" text,
    "n-given" text,
    "n-middle" text,
    "n-prefix" text,
    "n-suffix" text,
    "adr-street" text,
    "adr-extadd" text,
    "adr-pobox" text,
    "adr-locality" text,
    "adr-region" text,
    "adr-pcode" text,
    "adr-country" text,
    "geo-lat" text,
    "geo-lon" text,
    "org-orgname" text,
    "org-orgunit" text,
    "agent-extval" text,
    "sort-string" text,
    "desc" text,
    "note" text,
    "uid" text,
    
    "photo-type" text,
    "photo-binval" text,
    "photo-extval" text,
    
    "logo-type" text,
    "logo-binval" text,
    "logo-extval" text,
    
    "sound-phonetic" text,
    "sound-binval" text,
    "sound-extval" text,
    
    "key-type" text,
    "key-cred" text,
    
    "rev" text
    );

--
-- Offline message queue
-- Used by: mod_offline
--
CREATE TABLE "queue" (
    "collection-owner" text NOT NULL,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "xml" text NOT NULL );

CREATE INDEX i_queue_owner ON "queue"("collection-owner");

--
-- Private XML storage
-- Used by: mod_iq_private
--
CREATE TABLE "private" (
    "collection-owner" text NOT NULL,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "ns" text,
    "xml" text,
    PRIMARY KEY ("collection-owner", "ns") );

CREATE INDEX i_private_owner ON "private"("collection-owner");

--
-- Message Of The Day (MOTD) messages (announcements)
-- Used by: mod_announce
--
CREATE TABLE "motd-message" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "xml" text NOT NULL);

--
-- Times of last MOTD message for each user
-- Used by: mod_announce
--
CREATE TABLE "motd-times" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "time" integer NOT NULL);

--
-- Default privacy list
-- Used by: mod_privacy
--
CREATE TABLE "privacy-default" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "default" text );

--
-- Privacy lists
-- Used by: mod_privacy
--
CREATE TABLE "privacy-items" (
    "collection-owner" text NOT NULL,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "list" text NOT NULL,
    "type" text,
    "value" text,
    "deny" boolean,
    "order" integer,
    "block" integer );

CREATE INDEX i_privacyi_owner ON "privacy-items"("collection-owner");

--
-- Vacation settings
-- Used by: mod_vacation
--
CREATE TABLE "vacation-settings" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint DEFAULT nextval('object-sequence'),
    "start" integer,
    "end" integer,
    "message" text );

--
-- User status information
-- Used by: mod_status
--
CREATE TABLE "status" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "status" text NOT NULL,
    "show" text,
    "last-login" int DEFAULT '0',
    "last-logout" int DEFAULT '0',
    "xml" text );
