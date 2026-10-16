-- A trimmed Magento 2.4 schema. Column names and types follow the real
-- tables, including the foreign keys Magento declares; most indexes and many
-- columns are left out.

CREATE TABLE store (
  store_id smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  code varchar(32) DEFAULT NULL,
  website_id smallint(5) unsigned NOT NULL DEFAULT 0,
  group_id smallint(5) unsigned NOT NULL DEFAULT 0,
  name varchar(255) NOT NULL,
  is_active smallint(5) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (store_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE core_config_data (
  config_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  scope varchar(8) NOT NULL DEFAULT 'default',
  scope_id int(11) NOT NULL DEFAULT 0,
  path varchar(255) NOT NULL DEFAULT 'general',
  value text,
  updated_at timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (config_id),
  UNIQUE KEY CORE_CONFIG_DATA_SCOPE_SCOPE_ID_PATH (scope, scope_id, path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE eav_entity_type (
  entity_type_id smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  entity_type_code varchar(50) NOT NULL,
  entity_table varchar(255) DEFAULT NULL,
  PRIMARY KEY (entity_type_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE eav_attribute (
  attribute_id smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  entity_type_id smallint(5) unsigned NOT NULL DEFAULT 0,
  attribute_code varchar(255) NOT NULL,
  backend_type varchar(8) NOT NULL DEFAULT 'static',
  frontend_input varchar(50) DEFAULT NULL,
  frontend_label varchar(255) DEFAULT NULL,
  is_required smallint(5) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (attribute_id),
  UNIQUE KEY EAV_ATTRIBUTE_ENTITY_TYPE_ID_ATTRIBUTE_CODE (entity_type_id, attribute_code),
  CONSTRAINT EAV_ATTRIBUTE_ENTITY_TYPE_ID_EAV_ENTITY_TYPE_ENTITY_TYPE_ID FOREIGN KEY (entity_type_id)
    REFERENCES eav_entity_type (entity_type_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE customer_entity (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  website_id smallint(5) unsigned DEFAULT NULL,
  email varchar(255) DEFAULT NULL,
  group_id smallint(5) unsigned NOT NULL DEFAULT 0,
  store_id smallint(5) unsigned DEFAULT 0,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  updated_at timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  is_active smallint(5) unsigned NOT NULL DEFAULT 1,
  created_in varchar(255) DEFAULT NULL,
  prefix varchar(40) DEFAULT NULL,
  firstname varchar(255) DEFAULT NULL,
  middlename varchar(255) DEFAULT NULL,
  lastname varchar(255) DEFAULT NULL,
  suffix varchar(40) DEFAULT NULL,
  dob date DEFAULT NULL,
  password_hash varchar(128) DEFAULT NULL,
  rp_token varchar(128) DEFAULT NULL,
  rp_token_created_at datetime DEFAULT NULL,
  default_billing int(10) unsigned DEFAULT NULL,
  default_shipping int(10) unsigned DEFAULT NULL,
  taxvat varchar(50) DEFAULT NULL,
  confirmation varchar(64) DEFAULT NULL,
  gender smallint(5) unsigned DEFAULT NULL,
  failures_num smallint(6) DEFAULT 0,
  first_failure timestamp NULL DEFAULT NULL,
  lock_expires timestamp NULL DEFAULT NULL,
  PRIMARY KEY (entity_id),
  UNIQUE KEY CUSTOMER_ENTITY_EMAIL_WEBSITE_ID (email, website_id),
  CONSTRAINT CUSTOMER_ENTITY_STORE_ID_STORE_STORE_ID FOREIGN KEY (store_id) REFERENCES store (store_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE customer_entity_varchar (
  value_id int(11) NOT NULL AUTO_INCREMENT,
  attribute_id smallint(5) unsigned NOT NULL DEFAULT 0,
  entity_id int(10) unsigned NOT NULL DEFAULT 0,
  value varchar(255) DEFAULT NULL,
  PRIMARY KEY (value_id),
  UNIQUE KEY CUSTOMER_ENTITY_VARCHAR_ENTITY_ID_ATTRIBUTE_ID (entity_id, attribute_id),
  KEY CUSTOMER_ENTITY_VARCHAR_ATTRIBUTE_ID (attribute_id),
  CONSTRAINT CUSTOMER_ENTITY_VARCHAR_ATTRIBUTE_ID_EAV_ATTRIBUTE_ATTRIBUTE_ID FOREIGN KEY (attribute_id)
    REFERENCES eav_attribute (attribute_id) ON DELETE CASCADE,
  CONSTRAINT CUSTOMER_ENTITY_VARCHAR_ENTITY_ID_CUSTOMER_ENTITY_ENTITY_ID FOREIGN KEY (entity_id)
    REFERENCES customer_entity (entity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE customer_address_entity (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  parent_id int(10) unsigned DEFAULT NULL,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  is_active smallint(5) unsigned NOT NULL DEFAULT 1,
  city varchar(255) NOT NULL,
  company varchar(255) DEFAULT NULL,
  country_id varchar(255) NOT NULL,
  fax varchar(255) DEFAULT NULL,
  firstname varchar(255) NOT NULL,
  lastname varchar(255) NOT NULL,
  postcode varchar(255) DEFAULT NULL,
  region varchar(255) DEFAULT NULL,
  region_id int(10) unsigned DEFAULT NULL,
  street text NOT NULL,
  telephone varchar(255) NOT NULL,
  vat_id varchar(255) DEFAULT NULL,
  vat_is_valid int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (entity_id),
  KEY CUSTOMER_ADDRESS_ENTITY_PARENT_ID (parent_id),
  CONSTRAINT CUSTOMER_ADDRESS_ENTITY_PARENT_ID_CUSTOMER_ENTITY_ENTITY_ID FOREIGN KEY (parent_id)
    REFERENCES customer_entity (entity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE customer_grid_flat (
  entity_id int(10) unsigned NOT NULL,
  name text,
  email varchar(255) DEFAULT NULL,
  created_at timestamp NULL DEFAULT NULL,
  dob date DEFAULT NULL,
  gender int(11) DEFAULT NULL,
  taxvat varchar(255) DEFAULT NULL,
  shipping_full text,
  billing_full text,
  billing_firstname varchar(255) DEFAULT NULL,
  billing_lastname varchar(255) DEFAULT NULL,
  billing_telephone varchar(255) DEFAULT NULL,
  billing_postcode varchar(255) DEFAULT NULL,
  billing_country_id varchar(255) DEFAULT NULL,
  billing_city varchar(255) DEFAULT NULL,
  billing_street varchar(255) DEFAULT NULL,
  PRIMARY KEY (entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE quote (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  store_id smallint(5) unsigned NOT NULL DEFAULT 0,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  is_active smallint(5) unsigned DEFAULT 1,
  customer_id int(10) unsigned DEFAULT NULL,
  customer_email varchar(255) DEFAULT NULL,
  customer_firstname varchar(255) DEFAULT NULL,
  customer_lastname varchar(255) DEFAULT NULL,
  remote_ip varchar(45) DEFAULT NULL,
  password_hash varchar(255) DEFAULT NULL,
  grand_total decimal(20,4) DEFAULT 0.0000,
  PRIMARY KEY (entity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE sales_order (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  state varchar(32) DEFAULT NULL,
  status varchar(32) DEFAULT NULL,
  protect_code varchar(255) DEFAULT NULL,
  customer_id int(10) unsigned DEFAULT NULL,
  quote_id int(10) unsigned DEFAULT NULL,
  increment_id varchar(32) DEFAULT NULL,
  grand_total decimal(20,4) DEFAULT NULL,
  customer_email varchar(128) DEFAULT NULL,
  customer_firstname varchar(128) DEFAULT NULL,
  customer_lastname varchar(128) DEFAULT NULL,
  customer_dob datetime DEFAULT NULL,
  customer_taxvat varchar(32) DEFAULT NULL,
  customer_gender int(11) DEFAULT NULL,
  remote_ip varchar(45) DEFAULT NULL,
  x_forwarded_for varchar(255) DEFAULT NULL,
  customer_note text,
  send_email smallint(5) unsigned DEFAULT NULL,
  email_sent smallint(5) unsigned DEFAULT NULL,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (entity_id),
  UNIQUE KEY SALES_ORDER_INCREMENT_ID_STORE_ID (increment_id),
  KEY SALES_ORDER_CUSTOMER_ID (customer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE sales_order_address (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  parent_id int(10) unsigned DEFAULT NULL,
  customer_address_id int(11) DEFAULT NULL,
  region_id int(11) DEFAULT NULL,
  customer_id int(11) DEFAULT NULL,
  fax varchar(255) DEFAULT NULL,
  region varchar(255) DEFAULT NULL,
  postcode varchar(255) DEFAULT NULL,
  lastname varchar(255) DEFAULT NULL,
  street varchar(255) DEFAULT NULL,
  city varchar(255) DEFAULT NULL,
  email varchar(255) DEFAULT NULL,
  telephone varchar(255) DEFAULT NULL,
  country_id varchar(2) DEFAULT NULL,
  firstname varchar(255) DEFAULT NULL,
  address_type varchar(255) DEFAULT NULL,
  company varchar(255) DEFAULT NULL,
  vat_id text,
  PRIMARY KEY (entity_id),
  KEY SALES_ORDER_ADDRESS_PARENT_ID (parent_id),
  CONSTRAINT SALES_ORDER_ADDRESS_PARENT_ID_SALES_ORDER_ENTITY_ID FOREIGN KEY (parent_id)
    REFERENCES sales_order (entity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE sales_order_payment (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  parent_id int(10) unsigned NOT NULL,
  method varchar(128) DEFAULT NULL,
  cc_exp_month varchar(12) DEFAULT NULL,
  cc_exp_year varchar(4) DEFAULT NULL,
  cc_last_4 varchar(100) DEFAULT NULL,
  cc_owner varchar(128) DEFAULT NULL,
  cc_type varchar(32) DEFAULT NULL,
  cc_number_enc varchar(128) DEFAULT NULL,
  last_trans_id varchar(255) DEFAULT NULL,
  additional_information text,
  PRIMARY KEY (entity_id),
  KEY SALES_ORDER_PAYMENT_PARENT_ID (parent_id),
  CONSTRAINT SALES_ORDER_PAYMENT_PARENT_ID_SALES_ORDER_ENTITY_ID FOREIGN KEY (parent_id)
    REFERENCES sales_order (entity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE newsletter_subscriber (
  subscriber_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  store_id smallint(5) unsigned DEFAULT 0,
  change_status_at timestamp NULL DEFAULT NULL,
  customer_id int(10) unsigned NOT NULL DEFAULT 0,
  subscriber_email varchar(150) DEFAULT NULL,
  subscriber_status int(11) NOT NULL DEFAULT 0,
  subscriber_confirm_code varchar(32) DEFAULT 'NULL',
  PRIMARY KEY (subscriber_id),
  KEY NEWSLETTER_SUBSCRIBER_CUSTOMER_ID (customer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE admin_user (
  user_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  firstname varchar(32) DEFAULT NULL,
  lastname varchar(32) DEFAULT NULL,
  email varchar(128) DEFAULT NULL,
  username varchar(40) DEFAULT NULL,
  password varchar(255) NOT NULL,
  created timestamp NOT NULL DEFAULT current_timestamp(),
  logdate timestamp NULL DEFAULT NULL,
  lognum smallint(5) unsigned NOT NULL DEFAULT 0,
  is_active smallint(6) NOT NULL DEFAULT 1,
  extra text,
  rp_token text,
  rp_token_created_at timestamp NULL DEFAULT NULL,
  PRIMARY KEY (user_id),
  UNIQUE KEY ADMIN_USER_USERNAME (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE customer_visitor (
  visitor_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  customer_id int(11) DEFAULT NULL,
  session_id varchar(1) DEFAULT NULL,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  last_visit_at timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (visitor_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE vault_payment_token (
  entity_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  customer_id int(10) unsigned DEFAULT NULL,
  public_hash varchar(128) NOT NULL,
  payment_method_code varchar(128) NOT NULL,
  type varchar(128) NOT NULL,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  expires_at timestamp NULL DEFAULT NULL,
  gateway_token varchar(255) NOT NULL,
  details text,
  is_active tinyint(1) NOT NULL DEFAULT 1,
  is_visible tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (entity_id),
  UNIQUE KEY VAULT_PAYMENT_TOKEN_HASH_UNIQUE_INDEX_PUBLIC_HASH (public_hash),
  CONSTRAINT VAULT_PAYMENT_TOKEN_CUSTOMER_ID_CUSTOMER_ENTITY_ENTITY_ID FOREIGN KEY (customer_id)
    REFERENCES customer_entity (entity_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

CREATE TABLE cron_schedule (
  schedule_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  job_code varchar(255) NOT NULL DEFAULT '0',
  status varchar(7) NOT NULL DEFAULT 'pending',
  messages text,
  created_at timestamp NOT NULL DEFAULT current_timestamp(),
  scheduled_at timestamp NULL DEFAULT NULL,
  PRIMARY KEY (schedule_id),
  KEY CRON_SCHEDULE_JOB_CODE_STATUS_SCHEDULED_AT (job_code, status, scheduled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;
