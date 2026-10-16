package preset

import (
	"fmt"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

const lv = "laravel"

// laravel handles Laravel applications, recognised by their migrations
// table, including the tables of first-party packages (Cashier, Passport,
// Sanctum, Telescope, Pulse).
func (e *env) laravel() bool {
	if !e.has("migrations", "migration", "batch") {
		return false
	}
	pl := model.Platform{Name: lv, Label: "Laravel"}
	if n, err := e.count("SELECT COUNT(*) FROM `migrations`"); err == nil {
		pl.Details = append(pl.Details, fmt.Sprintf("%d migrations", n))
	}
	e.res.Platforms = append(e.res.Platforms, pl)

	e.column("sessions", "payload", hint(lv, model.CatSessionData, "serialized session data"))
	e.column("cache", "value", hint(lv, model.CatSessionData, "cached application data"))
	e.column("subscriptions", "stripe_id", hint(lv, model.CatPaymentToken, "Stripe subscription ID"))
	e.column("oauth_clients", "secret", hint(lv, model.CatSecret, "OAuth client secret"))

	for t, why := range map[string]string{
		"sessions":               "active login sessions",
		"password_reset_tokens":  "password reset tokens",
		"password_resets":        "password reset tokens",
		"personal_access_tokens": "API tokens of real users",
		"jobs":                   "queued jobs would run when a queue worker starts on staging",
		"failed_jobs":            "failed job payloads and stack traces often hold personal data",
		"cache":                  "cached data from production",
		"cache_locks":            "cache locks",
		"telescope_entries":      "Telescope debug records include request payloads",
		"telescope_entries_tags": "Telescope debug records",
		"telescope_monitoring":   "Telescope debug records",
		"pulse_entries":          "Pulse monitoring records",
		"pulse_values":           "Pulse monitoring records",
		"pulse_aggregates":       "Pulse monitoring records",
		"oauth_access_tokens":    "OAuth access tokens",
		"oauth_refresh_tokens":   "OAuth refresh tokens",
		"oauth_auth_codes":       "OAuth authorisation codes",
	} {
		e.action(t, "truncate", why)
	}

	if e.has("jobs", "queue") {
		total, err := e.count("SELECT COUNT(*) FROM `jobs`")
		if err != nil {
			e.warn(fmt.Sprintf("could not count queued jobs: %v", err))
		} else if total > 0 {
			rows, _ := e.rows("SELECT queue, COUNT(*) FROM " + sample.QuoteIdent("jobs") + " GROUP BY queue ORDER BY COUNT(*) DESC LIMIT 5")
			e.sideEffect(model.SideEffect{
				Platform: lv, Kind: "queued_jobs", Table: "jobs", Severity: model.SeverityMedium, Count: total,
				Summary: fmt.Sprintf("%d queued jobs would run when a queue worker starts on staging (queues: %s)", total, topCounts(rows, 3)),
				Fix:     "Empty the jobs table in the copy",
			})
		}
	}
	return true
}
