--
-- This script migrates jabberd14 xdb_sql postgresql data
-- to jabberd2 postgres storage
--

-- \i db-setup.pgsql

-- notatki:
-- wszystko pozostale skonwertowac konwerterem jajcusia
-- zmodyfikowac formularz modyfikacji danych usera
-- zmodyfikowac proces odzyskiwania hasla
ALTER TABLE recovery RENAME COLUMN mailaddress TO email;
ALTER TABLE recovery ADD COLUMN "collection-owner" text;
UPDATE recovery SET "collection-owner" = username || '@' || realm;
ALTER TABLE recovery ALTER COLUMN "collection-owner" SET not null;
ALTER TABLE recovery DROP COLUMN username;
ALTER TABLE recovery DROP COLUMN realm;

CREATE TABLE userdata (
 "collection-owner" text PRIMARY KEY,
 lastmodified timestamp not null default current_timestamp,
 name varchar(256),
 email varchar(512),
 wwwstatus boolean not null default false,
 profilesearch boolean not null default true );
INSERT INTO userdata ("collection-owner",lastmodified,name,email,wwwstatus,profilesearch) SELECT u.username || '@' || u.realm, COALESCE(lastmodified,now()), name, mailaddress, wwwstatus, profilesearch FROM useroptions AS u LEFT JOIN mailaddresses AS m ON (u.username = m.username AND u.realm = m.realm);
DROP TABLE mailaddresses;
DROP TABLE useroptions;

--
-- Drop unconvertable and unused tables first
--
DROP TABLE presence;
DROP TABLE roster; -- It's support is buggy in jabberd14 so I haven't used it.

--
-- Convert user data
--
ALTER TABLE authreg ADD COLUMN created timestamp DEFAULT current_timestamp;
INSERT INTO authreg (username,realm,password) SELECT username,realm,password FROM users;
DROP TABLE users;

--
-- Convert offline storage
--
ALTER TABLE queue ADD COLUMN storetime timestamp not null default current_timestamp;
INSERT INTO queue ("collection-owner",xml,storetime) SELECT username || '@' || realm, xml, storetime FROM messages WHERE xml != '';
DROP TABLE messages;

--
-- Convert vCard data
--
INSERT INTO vcard ("collection-owner",
"fn","nickname","url","tel","email","title","role",
"bday","tz",
"n-family","n-given","n-middle","n-prefix","n-suffix",
"adr-street","adr-extadd","adr-pobox","adr-locality","adr-region","adr-pcode","adr-country",
"geo-lat","geo-lon","org-orgname","org-orgunit","agent-extval","sort-string","desc","note",
"photo-type","photo-binval","photo-extval","logo-type","logo-binval","logo-extval",
"sound-phonetic","sound-binval","sound-extval","key-type","key-cred","rev"
) SELECT username || '@' || realm,
display_name,nickname,homepage,landline,email,job_title,org_role,
TRIM(TO_CHAR(birth_year,'0000'))||'-'||TRIM(TO_CHAR(birth_month,'00'))||'-'||TRIM(TO_CHAR(birth_dayofmonth,'00')),'',
family_name,given_name,middle_name,name_prefix,name_suffix,
street,building || ' / ' || room,postalbox,locality,region,postalcode,country,
lat,lon,org_name,org_unit,'','',description,'JEP-0054 vcard-temp',
photo_data_mime,photo_data,photo_url,'','','',
'','','','',pgpkey,timestamp FROM userprofile;

DROP TABLE userprofile;

--
-- Convert iq-last data
--
INSERT INTO logout ("collection-owner",time) SELECT username || '@' || realm, (substring(substring(xml from 'last=.[0-9]+') from '[0-9]+'))::integer FROM last;
DROP TABLE last;
