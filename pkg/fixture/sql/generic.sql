-- A schema no preset knows: small invented versions of the shapes found in
-- old forum, billing, shop and custom-app databases, and tables that look
-- like key/value stores but hold people.

-- Forum-style
CREATE TABLE admin_login_logs (
  admin_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  admin_username varchar(255) NOT NULL DEFAULT '',
  admin_time int(10) unsigned NOT NULL DEFAULT 0,
  admin_post_details text,
  PRIMARY KEY (admin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE members (
  member_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  name varchar(255) NOT NULL DEFAULT '',
  email varchar(150) NOT NULL DEFAULT '',
  members_display_name varchar(255) NOT NULL DEFAULT '',
  members_seo_name varchar(255) NOT NULL DEFAULT '',
  member_login_key varchar(32) NOT NULL DEFAULT '',
  hwid text,
  bday_day int(2) DEFAULT NULL,
  bday_month int(2) DEFAULT NULL,
  bday_year int(4) DEFAULT NULL,
  members_pass_hash varchar(32) NOT NULL DEFAULT '',
  members_pass_salt varchar(5) NOT NULL DEFAULT '',
  regip varbinary(16) DEFAULT NULL,
  lastip binary(16) DEFAULT NULL,
  poster_ip varbinary(16) DEFAULT NULL,
  device_uuid binary(16) DEFAULT NULL,
  ip_hash binary(16) DEFAULT NULL,
  PRIMARY KEY (member_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE message_topics (
  mt_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  mt_title varchar(255) NOT NULL DEFAULT '',
  mt_starter_id int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (mt_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE inline_notifications (
  notify_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  notify_to_id int(10) unsigned NOT NULL DEFAULT 0,
  notify_text text,
  PRIMARY KEY (notify_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE content_cache_posts (
  cache_content_id int(10) unsigned NOT NULL DEFAULT 0,
  cache_content mediumtext,
  cache_updated int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (cache_content_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE cache_store (
  cs_key varchar(255) NOT NULL DEFAULT '',
  cs_value mediumtext,
  cs_updated int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (cs_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE banfilters (
  ban_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  ban_type varchar(10) NOT NULL DEFAULT '',
  ban_content text,
  PRIMARY KEY (ban_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Billing-style
CREATE TABLE setting (
  id bigint(20) NOT NULL AUTO_INCREMENT,
  param varchar(255) DEFAULT NULL,
  value text,
  PRIMARY KEY (id),
  UNIQUE KEY param (param)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE admin (
  id bigint(20) NOT NULL AUTO_INCREMENT,
  email varchar(255) DEFAULT NULL,
  pass varchar(255) DEFAULT NULL,
  salt varchar(255) DEFAULT NULL,
  name varchar(255) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Shop-style
CREATE TABLE ab_language_definitions (
  language_definition_id int(11) NOT NULL AUTO_INCREMENT,
  language_id int(11) NOT NULL DEFAULT 1,
  language_key varchar(170) NOT NULL DEFAULT '',
  language_value text NOT NULL,
  PRIMARY KEY (language_definition_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE ab_customer_groups (
  customer_group_id int(11) NOT NULL AUTO_INCREMENT,
  name varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (customer_group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Custom apps
CREATE TABLE settings (
  setting_name varchar(20) NOT NULL DEFAULT '',
  setting_value text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE donations (
  id int(11) NOT NULL AUTO_INCREMENT,
  data text,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE paypal_ipn (
  id int(11) NOT NULL AUTO_INCREMENT,
  ipn_data text,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE game_logs (
  id int(11) NOT NULL AUTO_INCREMENT,
  summonername varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE form_entries (
  id int(11) NOT NULL AUTO_INCREMENT,
  entry_id int(11) NOT NULL DEFAULT 0,
  field_key varchar(191) NOT NULL DEFAULT '',
  field_value text,
  PRIMARY KEY (id),
  KEY field_key (field_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Shaped like key/value stores, but holding people: they stay plain tables.
CREATE TABLE contacts (
  id int(11) NOT NULL AUTO_INCREMENT,
  contact_name varchar(255) NOT NULL DEFAULT '',
  contact_value text,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE customers (
  id int(11) NOT NULL AUTO_INCREMENT,
  customer_name varchar(255) NOT NULL DEFAULT '',
  customer_value text,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE member_settings (
  id int(11) NOT NULL AUTO_INCREMENT,
  member_name varchar(64) NOT NULL DEFAULT '',
  member_value text,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Keyed by people's names: the key-shape guard makes it a plain table.
CREATE TABLE kv (
  id int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(191) NOT NULL DEFAULT '',
  value text,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Integrations: one credential per secret format the scanner knows by its
-- shape, settings with credentials under paths, webhook columns, and
-- look-alikes that must not count (a placeholder DSN, a field name, a slug
-- and image data).
CREATE TABLE integrations (
  id int(11) NOT NULL AUTO_INCREMENT,
  service varchar(64) NOT NULL DEFAULT '',
  credential text,
  settings text,
  discord_webhook varchar(255) DEFAULT NULL,
  webhook_url varchar(255) DEFAULT NULL,
  docs_url varchar(255) DEFAULT NULL,
  plugin_option varchar(191) DEFAULT NULL,
  post_name varchar(191) DEFAULT NULL,
  photo mediumtext,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Logged API requests: Authorization headers as lines, print_r text and
-- serialized arrays, keys in URLs, a log line with escaped JSON, and
-- $_SERVER dumps with PHP_AUTH_PW.
CREATE TABLE api_request_log (
  id int(11) NOT NULL AUTO_INCREMENT,
  request_line varchar(255) DEFAULT NULL,
  request_headers text,
  headers text,
  request_url varchar(512) DEFAULT NULL,
  payload text,
  server_vars text,
  sample_header varchar(255) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Push notification tokens of an app's devices.
CREATE TABLE push_devices (
  id int(11) NOT NULL AUTO_INCREMENT,
  app_name varchar(64) NOT NULL DEFAULT '',
  registration_id varchar(255) DEFAULT NULL,
  expo_token varchar(191) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
