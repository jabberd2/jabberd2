--
-- This is the required schema for PostgreSQL. Load this into the
-- database using the psql interactive terminal:
--
--     template1=> \i db-setup.pgsql
--

CREATE DATABASE jabberd2;
\c jabberd2

--
-- c2s authentication/registration table
--
CREATE TABLE "authreg" (
    "username" varchar(256),
    "realm" varchar(256),
    "password" varchar(256),
    "token" varchar(10),
    "sequence" integer,
    "hash" varchar(40) );

CREATE SEQUENCE "object-sequence";

--
-- Session manager tables 
--

--
-- Active (seen) users
-- Used by: core
--
CREATE TABLE "active" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "time" integer );

--
-- Logout times
-- Used by: mod_iq_last
--
CREATE TABLE "logout" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "time" integer );

--
-- Roster items
-- Used by: mod_roster
--
CREATE TABLE "roster-items" (
    "collection-owner" text,
    "object-sequence" bigint,
    "jid" text,
    "name" text,
    "to" boolean,
    "from" boolean,
    "ask" integer );

--
-- Roster groups
-- Used by: mod_roster
--
CREATE TABLE "roster-groups" (
    "collection-owner" text,
    "object-sequence" bigint,
    "jid" text,
    "group" text );

--
-- vCard (user profile information)
-- Used by: mod_iq_vcard
--
CREATE TABLE "vcard" (
    "collection-owner" text,
    "object-sequence" bigint,
    "fn" text,
    "nickname" text,
    "url" text,
    "tel" text,
    "email" text,
    "title" text,
    "role" text,
    "bday" text,
    "desc" text,
    "n-given" text,
    "n-family" text,
    "adr-street" text,
    "adr-extadd" text,
    "adr-locality" text,
    "adr-region" text,
    "adr-pcode" text,
    "adr-country" text,
    "org-orgname" text,
    "org-orgunit" text );

--
-- Offline message queue
-- Used by: mod_offline
--
CREATE TABLE "queue" (
    "collection-owner" text,
    "object-sequence" bigint,
    "xml" text );

--
-- Private XML storage
-- Used by: mod_iq_private
--
CREATE TABLE "private" (
    "collection-owner" text,
    "object-sequence" bigint,
    "ns" text,
    "xml" text );

--
-- Message Of The Day (MOTD) messages (announcements)
-- Used by: mod_announce
--
CREATE TABLE "motd-message" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "xml" text );

--
-- Times of last MOTD message for each user
-- Used by: mod_announce
--
CREATE TABLE "motd-times" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "time" integer );

--
-- User-published discovery items
-- Used by: mod_disco_publish
--
CREATE TABLE "disco-items" (
    "collection-owner" text,
    "object-sequence" bigint,
    "jid" text,
    "name" text,
    "node" text );

--
-- Default privacy list
-- Used by: mod_privacy
--
CREATE TABLE "privacy-default" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "default" text );

--
-- Privacy lists
-- Used by: mod_privacy
--
CREATE TABLE "privacy-items" (
    "collection-owner" text,
    "object-sequence" bigint,
    "list" text,
    "type" text,
    "value" text,
    "deny" boolean,
    "order" integer,
    "block" integer );

--
-- Vacation settings
-- Used by: mod_vacation
--
CREATE TABLE "vacation-settings" (
    "collection-owner" text PRIMARY KEY,
    "object-sequence" bigint,
    "start" int,
    "end" int,
    "message" text );
