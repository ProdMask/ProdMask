# prodmask scan: `shop`

- **Server:** MariaDB 11.8.9 at 127.0.0.1:3381, user `prodmask_ro`
- **Platforms:** WordPress (prefix wp_, db_version 60421); WooCommerce 9.3.3 (prefix wp_, orders in HPOS tables)
- **Scanned:** 28 tables, 9,100 rows sampled (up to 300 per table, and up to 20 per key in key/value tables), on 2026-11-25 13:58 UTC, in 278 ms
- **Tool:** prodmask 0.14.0. The report lists names, counts and categories only; it contains no sampled values.

## What a plain copy of this database would carry into staging

| Severity | Findings | Kinds of data |
|---|---:|---|
| Critical | 7 | secret, key or token (7) |
| High | 59 | email address (24), secret, key or token (13), street address (11), phone number (5), payment token or ID (4), free text with personal data (1), password hash (1) |
| Medium | 69 | person name (20), IP address (11), city (7), postcode (7), user agent (6), free text with personal data (5), username (4), geolocation (3), secret, key or token (3), payment token or ID (2), session data (1) |
| Low | 22 | country (8), card details (4), region or state (4), company name (3), personal website (3) |

## What staging could do to real people

| Staging would | Severity | What | Where | Fix in the copy |
|---|---|---|---|---|
| charge customers | Critical | 6 subscription renewal payments are scheduled; staging would try to charge customers when they fall due | `wp_actionscheduler_actions` `woocommerce_scheduled_subscription_payment` | Cancel these actions in the copy, or make sure WooCommerce Subscriptions starts in staging mode |
| send email | High | Outgoing email is sent through WP Mail SMTP (mailer: sendgrid) | `wp_options` `wp_mail_smtp` | Point the mailer at a mail catcher such as Mailpit, or turn it off, in the copy |
| take live payments | High | Payment gateway "stripe" is enabled in live mode | `wp_options` `woocommerce_stripe_settings` | Switch the gateway to test or sandbox mode and remove the live keys in the copy |
| post to webhooks | High | 2 active webhooks would send order and customer data from staging to their delivery URLs | `wp_wc_webhooks` | Set status to 'disabled' (or delete the rows) in the copy |
| upload backups | High | UpdraftPlus backups are scheduled and go to Amazon S3; staging would send its backups there too | `wp_options` `updraft_service` | Remove the remote storage in UpdraftPlus's settings in the copy, or turn its backup schedule off |
| email members | High | 2 WooCommerce Memberships emails are enabled; staging would send them to members, for example when a membership ends | `wp_options` | Turn these emails off in WooCommerce > Settings > Emails in the copy, or route mail to a catcher such as Mailpit |
| act as the live site | High | The copy keeps the live site's Jetpack connection; connected services would act for the live site, and WooCommerce Shipping, Tax or Payments are active | `wp_options` | Disconnect the copy: delete the blog token in jetpack_private_options and the auth entry in woocommerce_helper_data, or define JETPACK_STAGING_MODE in its wp-config.php |
| run scheduled actions | Medium | 40 pending scheduled actions would run on staging (most common: woocommerce_cleanup_draft_orders (20), wc-admin_import_orders (14), woocommerce_scheduled_subscription_payment (6)) | `wp_actionscheduler_actions` | Cancel pending actions in the copy, or turn off WP-Cron and Action Scheduler there |
| run cron events | Medium | 5 WP-Cron events would run on staging, including UpdraftPlus backups, WPForms email summaries, WooCommerce usage tracking and Ultimate Member jobs (most common: um_daily_scheduled_events (1), updraft_backup (1), woocommerce_tracker_send_event (1)) | `wp_options` `cron` | Turn cron off on the copy's host (DISABLE_WP_CRON stops runs on page loads, not a system cron), and change the plugins' own settings, since they schedule their events again |
| email store staff | Medium | WooCommerce emails store staff about new and cancelled orders; staging would email them too | `wp_options` `woocommerce_new_order_settings` | Set these emails to off in WooCommerce > Settings > Emails in the copy, or route mail to a catcher such as Mailpit |
| email staff | Medium | 1 plugin setting sends notification emails to staff addresses (for example fixture_admin_recipient) | `wp_options` | Point these settings at a test address, or route mail to a catcher such as Mailpit, in the copy |
| email form recipients | Medium | 1 Contact Form 7 form emails its submissions to the addresses in its settings | `wp_postmeta` `_mail` | Route mail to a catcher such as Mailpit in the copy, or add demo_mode: on to each form's Additional Settings |

## Findings

| Severity | Where | Data | Confidence | Evidence | Suggested mask |
|---|---|---|---|---|---|
| Critical | `wp_options.option_value[as3cf_settings] → access-key-id` | secret, key or token | high | secret formats found: AWS access key ID (1 live) | `null` |
| Critical | `wp_options.option_value[woocommerce_paypal_settings] → api_password` | secret, key or token | high | name contains "password"; 1 of 1 sampled values aren't password hashes: plain text or reversible encryption; a copy hands out working passwords | `null` |
| Critical | `wp_options.option_value[woocommerce_stripe_settings] → secret_key` | secret, key or token | high | name contains "secret key"; secret formats found: Stripe secret key (1 live) | `null` |
| Critical | `wp_options.option_value[woocommerce_stripe_settings] → webhook_secret` | secret, key or token | high | name contains "webhook secret"; secret formats found: Stripe webhook secret (1 live) | `null` |
| Critical | `wp_options.option_value[wp_mail_smtp] → sendgrid.api_key` | secret, key or token | high | name contains "api key"; secret formats found: SendGrid API key (1 live) | `null` |
| Critical | `wp_options.option_value[wpgmza_temp_api]` | secret, key or token | high | secret formats found: Google API key (1 live) | `null` |
| High | `wp_options.option_value[admin_email]` | email address | high | known field (wordpress preset); 1 of 1 sampled values match the email address format; site administrator | `fake_email` |
| High | `wp_options.option_value[fixture_admin_recipient]` | email address | high | name contains "recipient"; 1 of 1 sampled values match the email address format | `fake_email` |
| High | `wp_options.option_value[fixture_hashids_salt]` | secret, key or token | medium | name contains "salt" | `null` |
| High | `wp_options.option_value[jetpack_private_options] → blog_token` | secret, key or token | medium | name contains "token" | `null` |
| High | `wp_options.option_value[logged_in_salt]` | secret, key or token | high | known field (wordpress preset); authentication key or salt; a copy that keeps it trusts production login cookies | `null` |
| High | `wp_options.option_value[rank-math-options-titles] → facebook_secret` | secret, key or token | medium | name contains "secret" | `null` |
| High | `wp_options.option_value[secret_key]` | secret, key or token | high | known field (wordpress preset); authentication key or salt; a copy that keeps it trusts production login cookies | `null` |
| High | `wp_options.option_value[um_cache_userdata_*]` | email address | high | 60 keys; um_email_as_username_*: name contains "email"; 6 of 6 sampled values match the email address format; also holds: password hash, person name, username; Ultimate Member's per-user profile cache, password hash included; the plugin rebuilds it | `delete` |
| High | `wp_options.option_value[woocommerce_cancelled_order_settings] → recipient` | email address | high | name contains "recipient"; 1 of 1 sampled values match the email address format | `fake_email` |
| High | `wp_options.option_value[woocommerce_new_order_settings] → recipient` | email address | high | name contains "recipient"; 1 of 1 sampled values match the email address format | `fake_email` |
| High | `wp_options.option_value[woocommerce_paypal_settings] → api_signature` | secret, key or token | medium | name contains "api signature" | `null` |
| High | `wp_options.option_value[woocommerce_paypal_settings] → email` | email address | high | name contains "email"; 1 of 1 sampled values match the email address format | `fake_email` |
| High | `wp_options.option_value[woocommerce_paypal_settings] → sandbox_api_password` | secret, key or token | high | name contains "password"; 1 of 1 sampled values aren't password hashes: plain text or reversible encryption; a copy hands out working passwords | `null` |
| High | `wp_options.option_value[woocommerce_stripe_settings] → test_secret_key` | secret, key or token | high | name contains "secret key"; secret formats found: Stripe secret key (1 test); test-mode keys only | `null` |
| High | `wp_options.option_value[wp_mail_smtp] → mail.from_email` | email address | high | name contains "email"; 1 of 1 sampled values match the email address format | `fake_email` |
| High | `wp_options.option_value[wp_mail_smtp_mail_key]` | secret, key or token | high | known field (wordpress preset); WP Mail SMTP's key; it decrypts the SMTP password it stores | `null` |
| Medium | `wp_options.option_value[limit_login_lockouts] → {}` | IP address | medium | 2 of 2 sampled values look like IP addresses | `fake_ip` |
| Medium | `wp_options.option_value[limit_login_logged] → {}` | IP address | medium | 1 of 1 sampled values look like IP addresses | `fake_ip` |
| Medium | `wp_options.option_value[limit_login_retries] → {}` | IP address | medium | 1 of 1 sampled values look like IP addresses | `fake_ip` |
| Medium | `wp_options.option_value[limit_login_retries_valid] → {}` | IP address | medium | 1 of 1 sampled values look like IP addresses | `fake_ip` |
| Medium | `wp_options.option_value[woocommerce_paypal_settings] → api_username` | username | medium | name contains "user name" | `fake_username` |
| Critical | `wp_woocommerce_api_keys.consumer_secret` | secret, key or token | high | known field (woocommerce preset); secret formats found: WooCommerce API key (2 live); REST API secret | `null` |
| High | `wp_woocommerce_api_keys.consumer_key` | secret, key or token | high | known field (woocommerce preset); hashed REST API key | `null` |
| High | `wp_commentmeta.meta_value[akismet_as_submitted] → comment_author_email` | email address | high | name contains "email"; 121 of 121 sampled values match the email address format | `fake_email` |
| Medium | `wp_commentmeta.meta_value[akismet_as_submitted] → comment_author` | person name | medium | name contains "comment author" | `fake_name` |
| Medium | `wp_commentmeta.meta_value[akismet_as_submitted] → comment_content` | free text with personal data | medium | name contains "comment"; of 121 sampled text values, 8 contain email addresses, 10 contain phone numbers | `redact` |
| Medium | `wp_commentmeta.meta_value[akismet_as_submitted] → user_agent` | user agent | high | name contains "user agent"; 121 of 121 sampled values match the user agent format | `fake_user_agent` |
| Medium | `wp_commentmeta.meta_value[akismet_as_submitted] → user_ip` | IP address | high | name contains "ip"; 121 of 121 sampled values match the IP address format | `fake_ip` |
| Low | `wp_commentmeta.meta_value[akismet_as_submitted] → comment_author_url` | personal website | medium | name contains "author url" | `null` |
| High | `wp_comments.comment_author_email` | email address | high | name contains "email"; 140 of 140 sampled values match the email address format | `fake_email` |
| Medium | `wp_comments.comment_agent` | user agent | high | known field (wordpress preset); 130 of 130 sampled values match the user agent format | `fake_user_agent` |
| Medium | `wp_comments.comment_author` | person name | medium | name contains "comment author" | `fake_name` |
| Medium | `wp_comments.comment_author_IP` | IP address | high | name contains "ip"; 130 of 130 sampled values match the IP address format | `fake_ip` |
| Medium | `wp_comments.comment_content` | free text with personal data | medium | name contains "comment"; of 140 sampled text values, 8 contain email addresses, 10 contain phone numbers | `redact` |
| Low | `wp_comments.comment_author_url` | personal website | medium | name contains "author url" | `null` |
| High | `wp_postmeta.meta_value[_billing_address_1]` | street address | medium | name contains "address" | `fake_street` |
| High | `wp_postmeta.meta_value[_billing_address_index]` | street address | high | known field (woocommerce preset); of 21 sampled text values, 21 contain email addresses, 21 contain phone numbers; search index of the full address, email and phone; WooCommerce rebuilds it | `null` |
| High | `wp_postmeta.meta_value[_billing_email]` | email address | high | name contains "email"; 21 of 21 sampled values match the email address format | `fake_email` |
| High | `wp_postmeta.meta_value[_billing_phone]` | phone number | high | name contains "phone"; 21 of 21 sampled values match the phone number format | `fake_phone` |
| High | `wp_postmeta.meta_value[_mail] → recipient` | email address | high | name contains "recipient"; 1 of 2 sampled values match the email address format | `fake_email` |
| High | `wp_postmeta.meta_value[_shipping_address_1]` | street address | medium | name contains "address" | `fake_street` |
| High | `wp_postmeta.meta_value[_shipping_address_index]` | street address | high | known field (woocommerce preset); of 21 sampled text values, 21 contain email addresses, 21 contain phone numbers; search index of the full address, email and phone; WooCommerce rebuilds it | `null` |
| High | `wp_postmeta.meta_value[_stripe_customer_id]` | payment token or ID | medium | name contains "stripe customer id" | `null` |
| High | `wp_postmeta.meta_value[_stripe_source_id]` | payment token or ID | medium | name contains "stripe source id" | `null` |
| High | `wp_postmeta.meta_value[customer_email] → []` | email address | high | 2 of 2 sampled values look like email addresses | `fake_email` |
| Medium | `wp_postmeta.meta_value[_bbp_author_ip]` | IP address | high | name contains "ip"; 4 of 4 sampled values match the IP address format | `fake_ip` |
| Medium | `wp_postmeta.meta_value[_billing_city]` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_postmeta.meta_value[_billing_first_name]` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_postmeta.meta_value[_billing_last_name]` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_postmeta.meta_value[_billing_postcode]` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Medium | `wp_postmeta.meta_value[_customer_ip_address]` | IP address | high | name contains "ip address"; 21 of 21 sampled values match the IP address format | `fake_ip` |
| Medium | `wp_postmeta.meta_value[_customer_user_agent]` | user agent | high | name contains "user agent"; 21 of 21 sampled values match the user agent format | `fake_user_agent` |
| Medium | `wp_postmeta.meta_value[_mail] → sender` | free text with personal data | high | of 1 sampled text values, 1 contain email addresses | `redact` |
| Medium | `wp_postmeta.meta_value[_order_key]` | secret, key or token | high | known field (woocommerce preset); anyone with this key in a link can view the order | `null` |
| Medium | `wp_postmeta.meta_value[_shipping_city]` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_postmeta.meta_value[_shipping_first_name]` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_postmeta.meta_value[_shipping_last_name]` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_postmeta.meta_value[_shipping_postcode]` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Medium | `wp_postmeta.meta_value[_transaction_id]` | payment token or ID | high | 21 of 21 sampled values look like payment provider IDs | `null` |
| Low | `wp_postmeta.meta_value[_billing_company]` | company name | medium | name contains "company" | `fake_company` |
| Low | `wp_postmeta.meta_value[_billing_country]` | country | medium | name contains "country" | `keep` |
| Low | `wp_postmeta.meta_value[_billing_state]` | region or state | medium | name contains "billing state" | `keep` |
| Low | `wp_postmeta.meta_value[_shipping_country]` | country | medium | name contains "country" | `keep` |
| High | `wp_posts.post_title where post_type = 'user_request'` | email address | high | known field (wordpress preset); 1 of 1 sampled values match the email address format; privacy requests keep the requester's email address in the title | `fake_email` |
| Medium | `wp_posts.post_password` | secret, key or token | high | known field (woocommerce preset); WordPress post passwords in plain text, and the key of each order stored as a post | `keep`; `null` where `post_type IN ('shop_order', 'shop_order_refund', 'shop_order_placehold', 'shop_subscription')`; `null` where `post_type = 'user_request'` |
| High | `wp_um_metadata.um_value[mobile_number]` | phone number | high | name contains "mobile number"; 19 of 19 sampled values match the phone number format | `fake_phone` |
| High | `wp_usermeta.meta_key[um_email_as_username_*]` | email address | high | 6 keys; known key family; the key names hold personal data; a copy must rewrite them too | `fake_email` |
| High | `wp_usermeta.meta_value[billing_address_1]` | street address | medium | name contains "address" | `fake_street` |
| High | `wp_usermeta.meta_value[billing_email]` | email address | high | name contains "email"; 24 of 24 sampled values match the email address format | `fake_email` |
| High | `wp_usermeta.meta_value[billing_phone]` | phone number | high | name contains "phone"; 24 of 24 sampled values match the phone number format | `fake_phone` |
| High | `wp_usermeta.meta_value[session_tokens]` | secret, key or token | high | known field (wordpress preset); login sessions, with IP addresses and user agents | `delete` |
| High | `wp_usermeta.meta_value[shipping_address_1]` | street address | medium | name contains "address" | `fake_street` |
| High | `wp_usermeta.meta_value[um_email_as_username_*]` | email address | high | 6 keys; name contains "email"; 6 of 6 sampled values match the email address format | `fake_email` |
| Medium | `wp_usermeta.meta_value[billing_city]` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_usermeta.meta_value[billing_first_name]` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_usermeta.meta_value[billing_last_name]` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_usermeta.meta_value[billing_postcode]` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Medium | `wp_usermeta.meta_value[community-events-location]` | geolocation | high | known field (wordpress preset); IP address and city saved by the dashboard events widget | `null` |
| Medium | `wp_usermeta.meta_value[community-events-location] → ip` | IP address | high | name contains "ip"; 21 of 21 sampled values match the IP address format | `fake_ip` |
| Medium | `wp_usermeta.meta_value[community-events-location] → latitude` | geolocation | medium | name contains "latitude" | `null` |
| Medium | `wp_usermeta.meta_value[community-events-location] → longitude` | geolocation | medium | name contains "longitude" | `null` |
| Medium | `wp_usermeta.meta_value[description]` | free text with personal data | medium | known field (wordpress preset); of 8 sampled text values, 1 contain email addresses, 1 contain phone numbers; user biography | `redact` |
| Medium | `wp_usermeta.meta_value[first_name]` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_usermeta.meta_value[last_name]` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_usermeta.meta_value[nickname]` | person name | medium | name contains "nick name" | `fake_name` |
| Medium | `wp_usermeta.meta_value[session_tokens] → *.ip` | IP address | high | name contains "ip"; 24 of 24 sampled values match the IP address format | `fake_ip` |
| Medium | `wp_usermeta.meta_value[session_tokens] → *.ua` | user agent | high | 24 of 24 sampled values look like browser user agents | `fake_user_agent` |
| Medium | `wp_usermeta.meta_value[shipping_city]` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_usermeta.meta_value[shipping_first_name]` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_usermeta.meta_value[shipping_last_name]` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_usermeta.meta_value[shipping_postcode]` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Low | `wp_usermeta.meta_value[billing_company]` | company name | medium | name contains "company" | `fake_company` |
| Low | `wp_usermeta.meta_value[billing_country]` | country | medium | name contains "country" | `keep` |
| Low | `wp_usermeta.meta_value[billing_state]` | region or state | medium | name contains "billing state" | `keep` |
| Low | `wp_usermeta.meta_value[community-events-location] → country` | country | medium | name contains "country" | `keep` |
| Low | `wp_usermeta.meta_value[shipping_country]` | country | medium | name contains "country" | `keep` |
| High | `wp_users.display_name` | email address | medium | 10 of 60 sampled values look like email addresses; 10 of 60 values are email addresses; keep them email-shaped when masking | `fake_name` |
| High | `wp_users.user_activation_key` | secret, key or token | high | known field (wordpress preset); password reset key | `null` |
| High | `wp_users.user_email` | email address | high | name contains "email"; 60 of 60 sampled values match the email address format | `fake_email` |
| High | `wp_users.user_login` | email address | medium | 10 of 60 sampled values look like email addresses; 10 of 60 values are email addresses; keep them email-shaped when masking | `fake_username` |
| High | `wp_users.user_nicename` | email address | medium | 10 of 60 sampled values look like email addresses; 10 of 60 values are email addresses; keep them email-shaped when masking | `fake_username` |
| High | `wp_users.user_pass` | password hash | high | name contains "user pass"; 60 of 60 sampled values match the password hash format; hash formats: WordPress bcrypt 20, phpass 40 | `staging_password` |
| Medium | `wp_users.display_name` | person name | medium | name contains "display name" | `fake_name` |
| Medium | `wp_users.user_login` | username | medium | name contains "user login" | `fake_username` |
| Medium | `wp_users.user_nicename` | username | medium | name contains "nice name" | `fake_username` |
| Medium | `wp_users.user_url` | free text with personal data | medium | 1 of 11 sampled values have email addresses inside, such as in URLs | `redact` |
| Low | `wp_users.user_url` | personal website | medium | name contains "user url" | `null` |
| High | `wp_wc_customer_lookup.email` | email address | high | name contains "email"; 59 of 59 sampled values match the email address format | `fake_email` |
| Medium | `wp_wc_customer_lookup.city` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_wc_customer_lookup.first_name` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_wc_customer_lookup.last_name` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_wc_customer_lookup.postcode` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Medium | `wp_wc_customer_lookup.username` | username | medium | name contains "user name" | `fake_username` |
| Low | `wp_wc_customer_lookup.country` | country | medium | name contains "country" | `keep` |
| Low | `wp_wc_customer_lookup.state` | region or state | high | known field (woocommerce preset) | `keep` |
| High | `wp_wc_order_addresses.address_1` | street address | medium | name contains "address" | `fake_street` |
| High | `wp_wc_order_addresses.address_2` | street address | medium | name contains "address"; no non-empty values in the sample | `fake_street` |
| High | `wp_wc_order_addresses.email` | email address | high | name contains "email"; 300 of 300 sampled values match the email address format | `fake_email` |
| High | `wp_wc_order_addresses.phone` | phone number | high | name contains "phone"; 300 of 300 sampled values match the phone number format | `fake_phone` |
| Medium | `wp_wc_order_addresses.city` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_wc_order_addresses.first_name` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_wc_order_addresses.last_name` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_wc_order_addresses.postcode` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Low | `wp_wc_order_addresses.company` | company name | medium | name contains "company" | `fake_company` |
| Low | `wp_wc_order_addresses.country` | country | medium | name contains "country" | `keep` |
| Low | `wp_wc_order_addresses.state` | region or state | high | known field (woocommerce preset) | `keep` |
| High | `wp_wc_orders.billing_email` | email address | high | name contains "email"; 300 of 300 sampled values match the email address format | `fake_email` |
| High | `wp_wc_orders.customer_note` | free text with personal data | high | name contains "customer note"; of 89 sampled text values, 34 contain phone numbers, 2 contain card-like numbers; possible card numbers typed into free text | `redact` |
| Medium | `wp_wc_orders.ip_address` | IP address | high | name contains "ip address"; 300 of 300 sampled values match the IP address format | `fake_ip` |
| Medium | `wp_wc_orders.transaction_id` | payment token or ID | high | 300 of 300 sampled values look like payment provider IDs | `null` |
| Medium | `wp_wc_orders.user_agent` | user agent | high | name contains "user agent"; 300 of 300 sampled values match the user agent format | `fake_user_agent` |
| High | `wp_wc_orders_meta.meta_value[_billing_address_index]` | street address | high | known field (woocommerce preset); of 50 sampled text values, 50 contain email addresses, 50 contain phone numbers; search index of the full address, email and phone; WooCommerce rebuilds it | `null` |
| High | `wp_wc_orders_meta.meta_value[_shipping_address_index]` | street address | high | known field (woocommerce preset); of 50 sampled text values, 50 contain email addresses, 50 contain phone numbers; search index of the full address, email and phone; WooCommerce rebuilds it | `null` |
| High | `wp_wc_orders_meta.meta_value[_stripe_customer_id]` | payment token or ID | medium | name contains "stripe customer id" | `null` |
| Medium | `wp_wc_orders_meta.meta_value[_wc_order_attribution_user_agent]` | user agent | high | name contains "user agent"; 49 of 49 sampled values match the user agent format | `fake_user_agent` |
| High | `wp_wc_webhooks.secret` | secret, key or token | medium | name contains "secret" | `null` |
| High | `wp_woocommerce_payment_tokens.token` | payment token or ID | high | known field (woocommerce preset); saved payment method at the gateway | `null` |
| High | `wp_woocommerce_sessions.session_value → customer.address_1` | street address | medium | name contains "address" | `fake_street` |
| High | `wp_woocommerce_sessions.session_value → customer.email` | email address | high | name contains "email"; 25 of 25 sampled values match the email address format | `fake_email` |
| High | `wp_woocommerce_sessions.session_value → customer.phone` | phone number | high | name contains "phone"; 24 of 24 sampled values match the phone number format | `fake_phone` |
| Medium | `wp_woocommerce_sessions.session_value` | session data | high | known field (woocommerce preset); carts and checkout details of visitors | `null` |
| Medium | `wp_woocommerce_sessions.session_value → customer.city` | city | medium | name contains "city" | `fake_city` |
| Medium | `wp_woocommerce_sessions.session_value → customer.first_name` | person name | medium | name contains "first name" | `fake_first_name` |
| Medium | `wp_woocommerce_sessions.session_value → customer.last_name` | person name | medium | name contains "last name" | `fake_last_name` |
| Medium | `wp_woocommerce_sessions.session_value → customer.postcode` | postcode | medium | name contains "postcode" | `fake_postcode` |
| Low | `wp_woocommerce_sessions.session_value → customer.country` | country | medium | name contains "country" | `keep` |
| Medium | `wp_wc_order_operational_data.order_key` | secret, key or token | high | known field (woocommerce preset); anyone with this key in a link can view the order | `null` |
| Low | `wp_woocommerce_payment_tokenmeta.meta_value[card_type]` | card details | high | known field (woocommerce preset) | `keep` |
| Low | `wp_woocommerce_payment_tokenmeta.meta_value[expiry_month]` | card details | high | known field (woocommerce preset) | `keep` |
| Low | `wp_woocommerce_payment_tokenmeta.meta_value[expiry_year]` | card details | high | known field (woocommerce preset) | `keep` |
| Low | `wp_woocommerce_payment_tokenmeta.meta_value[last4]` | card details | high | known field (woocommerce preset) | `keep` |

5 low-confidence matches are left out here; the JSON report lists them.

## Tables to empty in the copy

| Table | Why |
|---|---|
| `wp_actionscheduler_logs` | background job logs |
| `wp_woocommerce_api_keys` | REST API credentials of the live store |
| `wp_woocommerce_sessions` | carts and checkout details of live visitors |

## Relationships

0 declared foreign keys; 26 inferred: 23 confirmed, 0 likely, 0 weak, 3 not checked.

| Status | Link | Evidence |
|---|---|---|
| confirmed | `wp_actionscheduler_actions.group_id → wp_actionscheduler_groups.group_id` | preset:woocommerce; 3 of 3 sampled values found |
| confirmed | `wp_actionscheduler_logs.action_id → wp_actionscheduler_actions.action_id` | preset:woocommerce; 100 of 100 sampled values found |
| confirmed | `wp_commentmeta.comment_id → wp_comments.comment_ID` | preset:wordpress; 100 of 100 sampled values found |
| confirmed | `wp_comments.comment_post_ID → wp_posts.ID` | preset:wordpress; 69 of 69 sampled values found |
| confirmed | `wp_comments.user_id → wp_users.ID` | preset:wordpress; 33 of 33 sampled values found |
| confirmed | `wp_postmeta.post_id → wp_posts.ID` | preset:wordpress; 100 of 100 sampled values found |
| confirmed | `wp_posts.post_author → wp_users.ID` | preset:wordpress; 5 of 5 sampled values found |
| confirmed | `wp_term_relationships.object_id → wp_posts.ID` | preset:wordpress; 70 of 70 sampled values found |
| confirmed | `wp_term_relationships.term_taxonomy_id → wp_term_taxonomy.term_taxonomy_id` | preset:wordpress; 12 of 12 sampled values found |
| confirmed | `wp_term_taxonomy.term_id → wp_terms.term_id` | preset:wordpress; 12 of 12 sampled values found |
| confirmed | `wp_um_metadata.user_id → wp_users.ID` | naming; 19 of 19 sampled values found |
| confirmed | `wp_usermeta.user_id → wp_users.ID` | preset:wordpress; 13 of 13 sampled values found |
| confirmed | `wp_wc_customer_lookup.user_id → wp_users.ID` | preset:woocommerce; 59 of 59 sampled values found |
| confirmed | `wp_wc_order_addresses.order_id → wp_wc_orders.id` | preset:woocommerce; 100 of 100 sampled values found |
| confirmed | `wp_wc_order_operational_data.order_id → wp_wc_orders.id` | preset:woocommerce; 100 of 100 sampled values found |
| confirmed | `wp_wc_orders.customer_id → wp_users.ID` | preset:woocommerce; 55 of 55 sampled values found |
| confirmed | `wp_wc_orders_meta.order_id → wp_wc_orders.id` | preset:woocommerce; 52 of 52 sampled values found |
| confirmed | `wp_wc_webhooks.user_id → wp_users.ID` | preset:woocommerce; 1 of 1 sampled values found |
| confirmed | `wp_woocommerce_api_keys.user_id → wp_users.ID` | preset:woocommerce; 1 of 1 sampled values found |
| confirmed | `wp_woocommerce_order_itemmeta.order_item_id → wp_woocommerce_order_items.order_item_id` | preset:woocommerce; 99 of 99 sampled values found |
| confirmed | `wp_woocommerce_order_items.order_id → wp_wc_orders.id` | preset:woocommerce; 100 of 100 sampled values found |
| confirmed | `wp_woocommerce_payment_tokenmeta.payment_token_id → wp_woocommerce_payment_tokens.token_id` | preset:woocommerce; 20 of 20 sampled values found |
| confirmed | `wp_woocommerce_payment_tokens.user_id → wp_users.ID` | preset:woocommerce; 19 of 19 sampled values found |
| unverified | `wp_comments.comment_parent → wp_comments.comment_ID` | preset:wordpress; no sampled values to check |
| unverified | `wp_posts.post_parent → wp_posts.ID` | preset:wordpress; no sampled values to check |
| unverified | `wp_wc_orders.parent_order_id → wp_wc_orders.id` | preset:woocommerce; no sampled values to check |

---

prodmask Pro copies this database with the real shape and fake customers: https://prodmask.com
