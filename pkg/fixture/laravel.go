package fixture

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// laravel fills a Laravel app: users with Cashier and Fortify columns,
// sessions, queued and failed jobs, Sanctum tokens, notifications, orders
// with JSON addresses, and polymorphic comments.
func (f *filler) laravel() {
	g := f.g
	var migrations [][]any
	for i, m := range []string{"0001_01_01_000000_create_users_table", "0001_01_01_000001_create_cache_table",
		"0001_01_01_000002_create_jobs_table", "2024_05_01_000000_create_personal_access_tokens_table",
		"2024_05_02_000000_add_two_factor_columns_to_users_table", "2024_05_03_000000_create_customer_columns",
		"2024_05_03_000001_create_subscriptions_table", "2024_06_01_000000_create_notifications_table",
		"2024_06_02_000000_create_posts_table", "2024_06_03_000000_create_orders_table",
		"2024_06_04_000000_create_comments_table"} {
		migrations = append(migrations, []any{m, 1 + i/4})
	}
	f.insert("migrations", []string{"migration", "batch"}, migrations)

	const nUsers = 120
	people := make([]person, nUsers+1)
	var users [][]any
	for id := 1; id <= nUsers; id++ {
		p := g.person(id)
		if id == 11 {
			p.email = f.canary + "@fixture-mail.gr"
		}
		people[id] = p
		var twoFactor, codes, stripe, pmType, last4 any
		if g.chance(0.25) {
			twoFactor = "eyJpdiI6I" + g.alnum(80)
			codes = "eyJpdiI6I" + g.alnum(160)
		}
		if g.chance(0.4) {
			stripe, pmType, last4 = "cus_"+g.alnum(14), "visa", fmt.Sprintf("%04d", g.intn(10000))
		}
		created := ts(g.date(2023, 2025))
		users = append(users, []any{id, p.first + " " + p.last, p.email, created, "$2y$12$" + g.chars(cryptChars, 53),
			g.alnum(60), twoFactor, codes, stripe, pmType, last4, created, created})
	}
	f.insert("users", []string{"id", "name", "email", "email_verified_at", "password", "remember_token",
		"two_factor_secret", "two_factor_recovery_codes", "stripe_id", "pm_type", "pm_last_four", "created_at", "updated_at"}, users)

	var resets [][]any
	for i := 0; i < 5; i++ {
		resets = append(resets, []any{people[2+i].email, "$2y$12$" + g.chars(cryptChars, 53)})
	}
	f.insert("password_reset_tokens", []string{"email", "token"}, resets)

	var sessions [][]any
	for i := 0; i < 60; i++ {
		var uid any
		p := g.person(500 + i)
		if g.chance(0.6) {
			u := 1 + g.intn(nUsers)
			uid, p = u, people[u]
		}
		payload := base64.StdEncoding.EncodeToString([]byte(php(kv{"_token", g.alnum(40),
			"_previous", kv{"url", "https://app.fixture-store.test/account"}, "_flash", kv{"old", []any{}, "new", []any{}}})))
		sessions = append(sessions, []any{g.alnum(40), uid, p.ip, p.agent, payload, 1760000000 + g.intn(900000)})
	}
	f.insert("sessions", []string{"id", "user_id", "ip_address", "user_agent", "payload", "last_activity"}, sessions)

	job := func(class string, props kv) string {
		cmd := fmt.Sprintf(`O:%d:"%s":%d:{`, len(class), class, len(props)/2)
		for i := 0; i+1 < len(props); i += 2 {
			cmd += php(props[i]) + php(props[i+1])
		}
		cmd += "}"
		return jsonString(map[string]any{"uuid": g.hex(8) + "-" + g.hex(4), "displayName": class,
			"job": "Illuminate\\Queue\\CallQueuedHandler@call", "maxTries": nil,
			"data": map[string]any{"commandName": class, "command": cmd}})
	}
	var jobs [][]any
	for i := 0; i < 12; i++ {
		p := people[1+g.intn(nUsers)]
		jobs = append(jobs, []any{g.pick([]string{"default", "emails"}),
			job("App\\Jobs\\SendInvoice", kv{"email", p.email, "name", p.first + " " + p.last, "orderId", 1 + g.intn(700)}),
			0, 1760000000, 1760000000})
	}
	f.insert("jobs", []string{"queue", "payload", "attempts", "available_at", "created_at"}, jobs)

	var failed [][]any
	for i := 0; i < 6; i++ {
		p := people[1+g.intn(nUsers)]
		failed = append(failed, []any{g.hex(8) + "-" + g.hex(4) + "-" + g.hex(4), "database", "emails",
			job("App\\Jobs\\SendInvoice", kv{"email", p.email, "orderId", 1 + g.intn(700)}),
			"Symfony\\Component\\Mailer\\Exception\\TransportException: Expected response code 250 but got 550 " +
				"for recipient " + p.email + " in /var/www/vendor/symfony/mailer/Transport/Smtp/SmtpTransport.php:342"})
	}
	f.insert("failed_jobs", []string{"uuid", "connection", "queue", "payload", "exception"}, failed)

	var tokens [][]any
	for i := 0; i < 20; i++ {
		tokens = append(tokens, []any{"App\\Models\\User", 1 + g.intn(nUsers), "mobile-app", sha256hex(g.alnum(40)), `["*"]`})
	}
	f.insert("personal_access_tokens", []string{"tokenable_type", "tokenable_id", "name", "token", "abilities"}, tokens)

	var notifications [][]any
	for i := 0; i < 150; i++ {
		uid := 1 + g.intn(nUsers)
		p := people[uid]
		data := map[string]any{"order_id": 1 + g.intn(700), "amount": fmt.Sprintf("%d.00", 10+g.intn(300)),
			"customer": map[string]any{"name": p.first + " " + p.last, "email": p.email, "phone": p.phone},
			"shipping": map[string]any{"line1": p.street, "city": p.city, "postcode": p.postcode}}
		if i == 4 {
			data["note"] = "for " + f.canary
		}
		notifications = append(notifications, []any{g.hex(8) + "-" + g.hex(4) + "-4" + g.hex(3) + "-a" + g.hex(3) + "-" + g.hex(12),
			"App\\Notifications\\OrderShipped", "App\\Models\\User", uid, jsonString(data)})
	}
	f.insert("notifications", []string{"id", "type", "notifiable_type", "notifiable_id", "data"}, notifications)

	var subs [][]any
	for i := 0; i < 30; i++ {
		subs = append(subs, []any{1 + g.intn(nUsers), "default", "sub_" + g.alnum(14), "active", "price_" + g.alnum(14), 1})
	}
	f.insert("subscriptions", []string{"user_id", "type", "stripe_id", "stripe_status", "stripe_price", "quantity"}, subs)

	var posts [][]any
	for id := 1; id <= 80; id++ {
		posts = append(posts, []any{id, 1 + g.intn(nUsers), "Post " + fmt.Sprint(id), g.sentence(30)})
	}
	f.insert("posts", []string{"id", "user_id", "title", "body"}, posts)

	var orders [][]any
	for id := 1; id <= 700; id++ {
		uid := 1 + g.intn(nUsers)
		p := people[uid]
		addr := jsonString(map[string]any{"name": p.first + " " + p.last, "line1": p.street, "city": p.city,
			"postcode": p.postcode, "country": p.country, "phone": p.phone})
		var notes any
		if id%10 == 0 {
			notes = "Call " + p.phone + " on arrival. " + g.sentence(5)
		}
		orders = append(orders, []any{id, uid, fmt.Sprintf("%d.%02d", 5+g.intn(400), g.intn(100)), addr, notes})
	}
	f.insert("orders", []string{"id", "user_id", "total", "shipping_address", "notes"}, orders)

	var comments [][]any
	for i := 0; i < 300; i++ {
		typ, target := "App\\Models\\Post", 1+g.intn(80)
		if i%3 == 0 {
			typ, target = "App\\Models\\Order", 1+g.intn(700)
		}
		comments = append(comments, []any{1 + g.intn(nUsers), typ, target, strings.TrimSpace(g.sentence(12))})
	}
	f.insert("comments", []string{"user_id", "commentable_type", "commentable_id", "body"}, comments)
}
