-- A trimmed WordPress + WooCommerce schema (WordPress 6.x, WooCommerce 9.x
-- with HPOS). Column names and types follow the real tables; some indexes
-- and rarely used columns are left out.

CREATE TABLE wp_users (
  ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_login varchar(60) NOT NULL DEFAULT '',
  user_pass varchar(255) NOT NULL DEFAULT '',
  user_nicename varchar(50) NOT NULL DEFAULT '',
  user_email varchar(100) NOT NULL DEFAULT '',
  user_url varchar(100) NOT NULL DEFAULT '',
  user_registered datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  user_activation_key varchar(255) NOT NULL DEFAULT '',
  user_status int(11) NOT NULL DEFAULT 0,
  display_name varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (ID),
  KEY user_login_key (user_login),
  KEY user_email (user_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_usermeta (
  umeta_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  meta_key varchar(255) DEFAULT NULL,
  meta_value longtext,
  PRIMARY KEY (umeta_id),
  KEY user_id (user_id),
  KEY meta_key (meta_key(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_posts (
  ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  post_author bigint(20) unsigned NOT NULL DEFAULT 0,
  post_date datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  post_date_gmt datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  post_content longtext NOT NULL,
  post_title text NOT NULL,
  post_excerpt text NOT NULL,
  post_status varchar(20) NOT NULL DEFAULT 'publish',
  comment_status varchar(20) NOT NULL DEFAULT 'open',
  ping_status varchar(20) NOT NULL DEFAULT 'open',
  post_password varchar(255) NOT NULL DEFAULT '',
  post_name varchar(200) NOT NULL DEFAULT '',
  post_modified datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  post_modified_gmt datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  post_parent bigint(20) unsigned NOT NULL DEFAULT 0,
  guid varchar(255) NOT NULL DEFAULT '',
  menu_order int(11) NOT NULL DEFAULT 0,
  post_type varchar(20) NOT NULL DEFAULT 'post',
  post_mime_type varchar(100) NOT NULL DEFAULT '',
  comment_count bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (ID),
  KEY type_status_date (post_type, post_status, post_date, ID),
  KEY post_parent (post_parent),
  KEY post_author (post_author)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_postmeta (
  meta_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  post_id bigint(20) unsigned NOT NULL DEFAULT 0,
  meta_key varchar(255) DEFAULT NULL,
  meta_value longtext,
  PRIMARY KEY (meta_id),
  KEY post_id (post_id),
  KEY meta_key (meta_key(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_comments (
  comment_ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  comment_post_ID bigint(20) unsigned NOT NULL DEFAULT 0,
  comment_author tinytext NOT NULL,
  comment_author_email varchar(100) NOT NULL DEFAULT '',
  comment_author_url varchar(200) NOT NULL DEFAULT '',
  comment_author_IP varchar(100) NOT NULL DEFAULT '',
  comment_date datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  comment_date_gmt datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  comment_content text NOT NULL,
  comment_karma int(11) NOT NULL DEFAULT 0,
  comment_approved varchar(20) NOT NULL DEFAULT '1',
  comment_agent varchar(255) NOT NULL DEFAULT '',
  comment_type varchar(20) NOT NULL DEFAULT 'comment',
  comment_parent bigint(20) unsigned NOT NULL DEFAULT 0,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (comment_ID),
  KEY comment_post_ID (comment_post_ID),
  KEY comment_author_email (comment_author_email(10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_commentmeta (
  meta_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  comment_id bigint(20) unsigned NOT NULL DEFAULT 0,
  meta_key varchar(255) DEFAULT NULL,
  meta_value longtext,
  PRIMARY KEY (meta_id),
  KEY comment_id (comment_id),
  KEY meta_key (meta_key(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_options (
  option_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  option_name varchar(191) NOT NULL DEFAULT '',
  option_value longtext NOT NULL,
  autoload varchar(20) NOT NULL DEFAULT 'yes',
  PRIMARY KEY (option_id),
  UNIQUE KEY option_name (option_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_terms (
  term_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  name varchar(200) NOT NULL DEFAULT '',
  slug varchar(200) NOT NULL DEFAULT '',
  term_group bigint(10) NOT NULL DEFAULT 0,
  PRIMARY KEY (term_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_term_taxonomy (
  term_taxonomy_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  term_id bigint(20) unsigned NOT NULL DEFAULT 0,
  taxonomy varchar(32) NOT NULL DEFAULT '',
  description longtext NOT NULL,
  parent bigint(20) unsigned NOT NULL DEFAULT 0,
  count bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (term_taxonomy_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_term_relationships (
  object_id bigint(20) unsigned NOT NULL DEFAULT 0,
  term_taxonomy_id bigint(20) unsigned NOT NULL DEFAULT 0,
  term_order int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (object_id, term_taxonomy_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_wc_orders (
  id bigint(20) unsigned NOT NULL,
  status varchar(20) DEFAULT NULL,
  currency varchar(10) DEFAULT NULL,
  type varchar(20) DEFAULT NULL,
  tax_amount decimal(26,8) DEFAULT NULL,
  total_amount decimal(26,8) DEFAULT NULL,
  customer_id bigint(20) unsigned DEFAULT NULL,
  billing_email varchar(320) DEFAULT NULL,
  date_created_gmt datetime DEFAULT NULL,
  date_updated_gmt datetime DEFAULT NULL,
  parent_order_id bigint(20) unsigned DEFAULT NULL,
  payment_method varchar(100) DEFAULT NULL,
  payment_method_title text,
  transaction_id varchar(100) DEFAULT NULL,
  ip_address varchar(100) DEFAULT NULL,
  user_agent text,
  customer_note text,
  PRIMARY KEY (id),
  KEY customer_id_billing_email (customer_id, billing_email(171))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_wc_order_addresses (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  order_id bigint(20) unsigned NOT NULL,
  address_type varchar(20) DEFAULT NULL,
  first_name text,
  last_name text,
  company text,
  address_1 text,
  address_2 text,
  city text,
  state text,
  postcode text,
  country text,
  email varchar(320) DEFAULT NULL,
  phone varchar(100) DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY address_type_order_id (address_type, order_id),
  KEY order_id (order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_wc_orders_meta (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  order_id bigint(20) unsigned DEFAULT NULL,
  meta_key varchar(255) DEFAULT NULL,
  meta_value text,
  PRIMARY KEY (id),
  KEY meta_key_value (meta_key(100), meta_value(82)),
  KEY order_id_meta_key_meta_value (order_id, meta_key(100), meta_value(82))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_wc_order_operational_data (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  order_id bigint(20) unsigned DEFAULT NULL,
  created_via varchar(100) DEFAULT NULL,
  woocommerce_version varchar(20) DEFAULT NULL,
  prices_include_tax tinyint(1) DEFAULT NULL,
  cart_hash varchar(100) DEFAULT NULL,
  new_order_email_sent tinyint(1) DEFAULT NULL,
  order_key varchar(100) DEFAULT NULL,
  date_paid_gmt datetime DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY order_id (order_id),
  KEY order_key (order_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_woocommerce_order_items (
  order_item_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  order_item_name text NOT NULL,
  order_item_type varchar(200) NOT NULL DEFAULT '',
  order_id bigint(20) unsigned NOT NULL,
  PRIMARY KEY (order_item_id),
  KEY order_id (order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_woocommerce_order_itemmeta (
  meta_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  order_item_id bigint(20) unsigned NOT NULL,
  meta_key varchar(255) DEFAULT NULL,
  meta_value longtext,
  PRIMARY KEY (meta_id),
  KEY order_item_id (order_item_id),
  KEY meta_key (meta_key(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_wc_customer_lookup (
  customer_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_id bigint(20) unsigned DEFAULT NULL,
  username varchar(60) NOT NULL DEFAULT '',
  first_name varchar(255) NOT NULL,
  last_name varchar(255) NOT NULL,
  email varchar(100) DEFAULT NULL,
  date_last_active timestamp NULL DEFAULT NULL,
  date_registered timestamp NULL DEFAULT NULL,
  country char(2) NOT NULL DEFAULT '',
  postcode varchar(20) NOT NULL DEFAULT '',
  city varchar(100) NOT NULL DEFAULT '',
  state varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (customer_id),
  UNIQUE KEY user_id (user_id),
  KEY email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_woocommerce_sessions (
  session_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  session_key char(32) NOT NULL,
  session_value longtext NOT NULL,
  session_expiry bigint(20) unsigned NOT NULL,
  PRIMARY KEY (session_id),
  UNIQUE KEY session_key (session_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_woocommerce_api_keys (
  key_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_id bigint(20) unsigned NOT NULL,
  description varchar(200) DEFAULT NULL,
  permissions varchar(10) NOT NULL,
  consumer_key char(64) NOT NULL,
  consumer_secret char(43) NOT NULL,
  nonces longtext,
  truncated_key char(7) NOT NULL,
  last_access datetime DEFAULT NULL,
  PRIMARY KEY (key_id),
  KEY consumer_key (consumer_key),
  KEY consumer_secret (consumer_secret)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_woocommerce_payment_tokens (
  token_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  gateway_id varchar(200) NOT NULL,
  token text NOT NULL,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  type varchar(200) NOT NULL,
  is_default tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (token_id),
  KEY user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_woocommerce_payment_tokenmeta (
  meta_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  payment_token_id bigint(20) unsigned NOT NULL,
  meta_key varchar(255) DEFAULT NULL,
  meta_value longtext,
  PRIMARY KEY (meta_id),
  KEY payment_token_id (payment_token_id),
  KEY meta_key (meta_key(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_wc_webhooks (
  webhook_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  status varchar(200) NOT NULL,
  name text NOT NULL,
  user_id bigint(20) unsigned NOT NULL,
  delivery_url text NOT NULL,
  secret text NOT NULL,
  topic varchar(200) NOT NULL,
  date_created datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  api_version smallint(4) NOT NULL,
  failure_count smallint(10) NOT NULL DEFAULT 0,
  PRIMARY KEY (webhook_id),
  KEY user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_actionscheduler_groups (
  group_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  slug varchar(255) NOT NULL,
  PRIMARY KEY (group_id),
  KEY slug (slug(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_actionscheduler_actions (
  action_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  hook varchar(191) NOT NULL,
  status varchar(20) NOT NULL,
  scheduled_date_gmt datetime DEFAULT '1000-01-01 00:00:00',
  args varchar(191) DEFAULT NULL,
  schedule longtext,
  group_id bigint(20) unsigned NOT NULL DEFAULT 0,
  attempts int(11) NOT NULL DEFAULT 0,
  extended_args varchar(8000) DEFAULT NULL,
  PRIMARY KEY (action_id),
  KEY hook_status_scheduled_date_gmt (hook(163), status, scheduled_date_gmt),
  KEY status_scheduled_date_gmt (status, scheduled_date_gmt),
  KEY group_id (group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;

CREATE TABLE wp_actionscheduler_logs (
  log_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  action_id bigint(20) unsigned NOT NULL,
  message text NOT NULL,
  log_date_gmt datetime DEFAULT '1000-01-01 00:00:00',
  PRIMARY KEY (log_id),
  KEY action_id (action_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
