--
-- upgrade script for jabberd2
--
\c jabberd2

-- #################################################################
-- changes from svn r2 -> r11
-- #################################################################
-- -- TABLE authreg
ALTER TABLE "authreg" ALTER COLUMN "username" TYPE varchar(1023);
ALTER TABLE "authreg" ALTER COLUMN "username" SET NOT NULL;
ALTER TABLE "authreg" ALTER COLUMN "realm" TYPE varchar(1023);
ALTER TABLE "authreg" ALTER COLUMN "realm" SET NOT NULL;

-- -- TABLE logout
ALTER TABLE "logout" ALTER COLUMN "time" SET NOT NULL;

-- -- TABLE roster-items
ALTER TABLE "roster-items" ALTER COLUMN "jid" SET NOT NULL;
ALTER TABLE "roster-items" ADD PRIMARY KEY ("collection-owner", "jid");
ALTER TABLE "roster-items" ALTER COLUMN "to" SET NOT NULL;
ALTER TABLE "roster-items" ALTER COLUMN "from" SET NOT NULL;
ALTER TABLE "roster-items" ALTER COLUMN "ask" SET NOT NULL;
ALTER TABLE "authreg" ADD PRIMARY KEY ("username", "realm");

-- -- TABLE roster-groups
ALTER TABLE "roster-groups" ALTER COLUMN "jid" SET NOT NULL;
ALTER TABLE "roster-groups" ALTER COLUMN "group" SET NOT NULL;
ALTER TABLE "roster-groups"
			ADD PRIMARY KEY ("collection-owner", "jid", "group");
CREATE INDEX i_rosterg_owner ON "roster-groups"("collection-owner");
CREATE INDEX i_rosterg_owner_jid ON "roster-groups"("collection-owner", "jid");

-- -- TABLE vcard
ALTER TABLE "vcard" ADD PRIMARY KEY ("collection-owner");
ALTER TABLE "vcard" ADD COLUMN "tz" TEXT;
ALTER TABLE "vcard" ADD COLUMN "n-middle" TEXT;
ALTER TABLE "vcard" ADD COLUMN "n-prefix" TEXT;
ALTER TABLE "vcard" ADD COLUMN "n-suffix" TEXT;
ALTER TABLE "vcard" ADD COLUMN "adr-pobox" TEXT;
ALTER TABLE "vcard" ADD COLUMN "geo-lat" TEXT;
ALTER TABLE "vcard" ADD COLUMN "geo-lon" TEXT;
ALTER TABLE "vcard" ADD COLUMN "agent-extval" TEXT;
ALTER TABLE "vcard" ADD COLUMN "sort-string" TEXT;
ALTER TABLE "vcard" ADD COLUMN "note" TEXT;
ALTER TABLE "vcard" ADD COLUMN "photo-type" TEXT;
ALTER TABLE "vcard" ADD COLUMN "photo-binval" TEXT;
ALTER TABLE "vcard" ADD COLUMN "photo-extval" TEXT;
ALTER TABLE "vcard" ADD COLUMN "logo-type" TEXT;
ALTER TABLE "vcard" ADD COLUMN "logo-binval" TEXT;
ALTER TABLE "vcard" ADD COLUMN "logo-extval" TEXT;
ALTER TABLE "vcard" ADD COLUMN "key-type" TEXT;
ALTER TABLE "vcard" ADD COLUMN "key-cred" TEXT;
ALTER TABLE "vcard" ADD COLUMN "rev" TEXT;

-- -- TABLE queue
ALTER TABLE "queue" ALTER COLUMN "xml" SET NOT NULL;
CREATE INDEX i_queue_owner ON "queue"("collection-owner");

-- -- TABLE private
ALTER TABLE "private" ALTER COLUMN "xml" SET NOT NULL;
ALTER TABLE "private" ADD PRIMARY KEY ("collection-owner", "ns");
CREATE INDEX i_private_owner ON "private"("collection-owner");

-- -- TABLE motd-message
ALTER TABLE "motd-message" ALTER COLUMN "xml" SET NOT NULL;

-- -- TABLE motd-times
ALTER TABLE "motd-times" ALTER COLUMN "time" SET NOT NULL;

-- -- TABLE disco-items
CREATE INDEX i_discoi_owner ON "disco-items"("collection-owner");

-- -- TABLE privacy-items
ALTER TABLE "privacy-items" ALTER COLUMN "list" SET NOT NULL;
CREATE INDEX i_privacyi_owner ON "privacy-items"("collection-owner");

-- -- TABLE status (new)
CREATE TABLE "status" (
	"collection-owner" TEXT PRIMARY KEY,
	"object-sequence" BIGINT,
	"status" TEXT NOT NULL,
	"show" TEXT,
	"last-login" INTEGER DEFAULT '0',
	"last-logout" INTEGER DEFAULT '0');

-- #################################################################
-- changes from svn r11 -> r16
-- 	tag: release_2_1
-- #################################################################

-- -- TABLE authreg
ALTER TABLE "authreg" ADD PRIMARY KEY ("username", "realm");
CREATE INDEX i_authreg_username ON "authreg"("username");
CREATE INDEX i_authreg_realm ON "authreg"("realm");

-- -- TABLE active
ALTER TABLE "active" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "active" ALTER COLUMN "time" SET NOT NULL;

-- -- TABLE logout
ALTER TABLE "logout" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "logout" ALTER COLUMN "time" SET NOT NULL;

-- -- TABLE roster-items
ALTER TABLE "roster-items" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "roster-items" ALTER COLUMN "collection-owner" SET NOT NULL;
CREATE INDEX i_rosteri_owner ON "roster-items"("collection-owner");

-- -- TABLE roster-groups
ALTER TABLE "roster-groups" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "roster-groups" ALTER COLUMN "collection-owner" SET NOT NULL;

-- -- TABLE "vcard"
ALTER TABLE "roster-groups" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');

-- -- TABLE queue
ALTER TABLE "queue" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "queue" ALTER COLUMN "collection-owner" SET NOT NULL;

-- -- TABLE private
ALTER TABLE "private" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "private" ALTER COLUMN "collection-owner" SET NOT NULL;

-- -- TABLE motd-times
ALTER TABLE "motd-times" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "motd-times" ALTER COLUMN "time" SET NOT NULL;

-- -- TABLE disco-items
ALTER TABLE "disco-items" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "disco-items" ALTER COLUMN "collection-owner" SET NOT NULL;

-- -- TABLE privacy-default
ALTER TABLE "privacy-default" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');

-- -- TABLE privacy-items
ALTER TABLE "privacy-items" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');
ALTER TABLE "privacy-items" ALTER COLUMN "collection-owner" SET NOT NULL;

-- -- TABLE vacation-settings
ALTER TABLE "vacation-settings" ALTER COLUMN "object-sequence" 
				SET DEFAULT NEXTVAL('object-sequence');

-- #####################################################################
-- changes from svn r16 -> r251
-- #####################################################################
ALTER TABLE "authreg" DROP COLUMN "token";
ALTER TABLE "authreg" DROP COLUMN "sequence";
ALTER TABLE "authreg" DROP COLUMN "hash";

-- #####################################################################
-- changes from svn r251 -> r431
-- #####################################################################
ALTER TABLE "status" ADD COLUMN "xml" TEXT;

-- #####################################################################
-- changes from svn r431 -> r464
-- #####################################################################
ALTER TABLE "vcard" ADD COLUMN "jabberid" TEXT;
ALTER TABLE "vcard" ADD COLUMN "mailer" TEXT;
ALTER TABLE "vcard" ADD COLUMN "uid" TEXT;
