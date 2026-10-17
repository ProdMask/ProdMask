package preset

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// wordpressEffects lists what a copy of a WordPress site would do to real
// people and services beyond its mail settings: scheduled events, backups,
// staff notifications, form mail and connected services. On multisite each
// kind is one side effect for the whole network, with a site count.
func (e *env) wordpressEffects(prefixes []string, base string, shops []string) {
	e.wordpressCron(prefixes, base)
	e.wooStaffEmails(shops)
	e.recipientSettings(prefixes)
	e.contactForm7(prefixes)
	e.membershipEmails(shops)
	e.connections(prefixes, base, shops)
	e.networkMail(base)
}

// sites renders " on 3 sites" for a network, and nothing for one site.
func sites(n int) string {
	if n > 1 {
		return fmt.Sprintf(" on %d sites", n)
	}
	return ""
}

// cronLabel names the scheduled hooks that reach people or services.
type cronLabel struct {
	prefix, label string
	people        bool   // raises the severity
	needs         string // a setting that must be on: "tracking" or "geoip"
}

var cronLabels = []cronLabel{
	{"updraft_backup", "UpdraftPlus backups", true, ""},
	{"wpforms_email_summaries_cron", "WPForms email summaries", true, ""},
	{"jetpack_sync_", "Jetpack sync", true, ""},
	{"woocommerce_tracker_send_event", "WooCommerce usage tracking", true, "tracking"},
	{"woocommerce_geoip_updater", "the MaxMind GeoIP download", true, "geoip"},
	{"um_", "Ultimate Member jobs", false, ""},
}

// cronEvents counts the events of a cron option by hook. WordPress keeps
// timestamp → hook → hash of the arguments → {schedule, args, interval}.
func cronEvents(raw string) map[string]int {
	counts := map[string]int{}
	detect.Walk(raw, func(path []string, _ string) {
		if len(path) == 4 && path[3] == "schedule" {
			counts[path[1]]++
		}
	})
	return counts
}

func (e *env) wordpressCron(prefixes []string, base string) {
	total, siteCount, truncated := 0, 0, false
	byHook := map[string]int{}
	labels := map[string]bool{}
	people := false
	var table, backupTable string
	var backupServices []string
	backups := false
	for _, p := range prefixes {
		opts := e.options(p+"options", "option_name", "option_value", []string{"cron", "woocommerce_allow_tracking",
			"woocommerce_maxmind_geolocation_settings", "updraft_service"})
		raw := opts["cron"]
		if raw == "" {
			continue
		}
		counts := cronEvents(raw)
		n := 0
		for hook, c := range counts {
			n += c
			byHook[hook] += c
		}
		if n == 0 {
			continue
		}
		total += n
		siteCount++
		truncated = truncated || len(raw) >= 65535
		if table == "" {
			table = p + "options"
		}
		on := map[string]bool{
			"tracking": yes(opts["woocommerce_allow_tracking"]),
			"geoip":    detect.Flatten(opts["woocommerce_maxmind_geolocation_settings"])["license_key"] != "",
		}
		for hook := range counts {
			for _, l := range cronLabels {
				if !strings.HasPrefix(hook, l.prefix) || (l.needs != "" && !on[l.needs]) {
					continue
				}
				labels[l.label] = true
				people = people || l.people
				if l.prefix == "updraft_backup" {
					backups = true
					services, from := opts["updraft_service"], p+"options"
					if services == "" {
						// Network-activated, UpdraftPlus keeps its settings for the network.
						services = e.options(base+"sitemeta", "meta_key", "meta_value", []string{"updraft_service"})["updraft_service"]
						from = base + "sitemeta"
					}
					if s := updraftServices(services); len(s) > 0 {
						backupServices = append(backupServices, s...)
						if backupTable == "" {
							backupTable = from
						}
					}
				}
			}
		}
	}
	if total == 0 {
		return
	}
	var named []string
	for _, l := range cronLabels {
		if labels[l.label] {
			named = append(named, l.label)
		}
	}
	including := ""
	if len(named) > 0 {
		including = ", including " + joinAnd(named)
	}
	atLeast := ""
	if truncated {
		atLeast = "at least "
	}
	sev := model.SeverityLow
	if people {
		sev = model.SeverityMedium
	}
	e.sideEffect(model.SideEffect{
		Platform: wp, Kind: "scheduled_jobs", Table: table, Item: "cron", Severity: sev, Count: int64(total),
		Summary: fmt.Sprintf("%s%s%s would run on staging%s (most common: %s)",
			atLeast, count(total, "WP-Cron event", "WP-Cron events"), sites(siteCount), including, topHooks(byHook, 3)),
		Fix: "Turn cron off on the copy's host (DISABLE_WP_CRON stops runs on page loads, not a system cron), " +
			"and change the plugins' own settings, since they schedule their events again",
	})
	if backups {
		e.updraftBackups(backupTable, backupServices)
	}
}

// Storage services of UpdraftPlus, by the IDs in its methods/ folder.
var updraftLabels = map[string]string{
	"s3": "Amazon S3", "s3generic": "S3-compatible storage", "dreamobjects": "DreamObjects", "backblaze": "Backblaze",
	"googlecloud": "Google Cloud Storage", "googledrive": "Google Drive", "dropbox": "Dropbox", "onedrive": "OneDrive",
	"azure": "Microsoft Azure", "openstack": "OpenStack Swift", "cloudfiles": "Rackspace Cloud Files",
	"webdav": "WebDAV", "ftp": "FTP", "sftp": "SFTP", "pcloud": "pCloud", "email": "email",
	"updraftvault": "UpdraftVault", "remotesend": "another site",
}

// updraftServices reads the updraft_service setting, a string or an array
// of service IDs, and returns labels for the remote ones.
func updraftServices(raw string) []string {
	var ids []string
	if !detect.Walk(raw, func(_ []string, v string) { ids = append(ids, v) }) {
		ids = []string{raw}
	}
	var out []string
	for _, id := range ids {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" || id == "none" {
			continue
		}
		label := updraftLabels[id]
		if label == "" {
			label = "remote storage"
		}
		out = append(out, label)
	}
	return out
}

func (e *env) updraftBackups(table string, services []string) {
	if len(services) == 0 {
		return
	}
	seen := map[string]bool{}
	var labels []string
	for _, s := range services {
		if !seen[s] {
			seen[s] = true
			labels = append(labels, s)
		}
	}
	sort.Strings(labels)
	e.sideEffect(model.SideEffect{
		Platform: wp, Kind: "backups", Table: table, Item: "updraft_service", Severity: model.SeverityHigh,
		Summary: fmt.Sprintf("UpdraftPlus backups are scheduled and go to %s; staging would send its backups there too", joinAnd(labels)),
		Fix:     "Remove the remote storage in UpdraftPlus's settings in the copy, or turn its backup schedule off",
	})
}

// The emails WooCommerce sends to the store's staff, which are on by
// default and go to the admin address unless a recipient is set.
var wooStaffEmails = []struct{ option, label string }{
	{"woocommerce_new_order_settings", "new"},
	{"woocommerce_cancelled_order_settings", "cancelled"},
	{"woocommerce_failed_order_settings", "failed"},
}

func (e *env) wooStaffEmails(shops []string) {
	siteCount := 0
	var table, item string
	on := map[string]bool{}
	for _, p := range shops {
		keys := make([]string, len(wooStaffEmails))
		for i, m := range wooStaffEmails {
			keys[i] = m.option
		}
		opts := e.options(p+"options", "option_name", "option_value", keys)
		enabled := false
		for _, m := range wooStaffEmails {
			raw, ok := opts[m.option]
			if ok && strings.EqualFold(strings.TrimSpace(detect.Flatten(raw)["enabled"]), "no") {
				continue
			}
			on[m.label] = true
			enabled = true
			if item == "" {
				item = m.option
			}
		}
		if enabled {
			siteCount++
			if table == "" {
				table = p + "options"
			}
		}
	}
	if siteCount == 0 {
		return
	}
	var kinds []string
	for _, m := range wooStaffEmails {
		if on[m.label] {
			kinds = append(kinds, m.label)
		}
	}
	e.sideEffect(model.SideEffect{
		Platform: wc, Kind: "email", Table: table, Item: item, Severity: model.SeverityMedium,
		Summary: fmt.Sprintf("WooCommerce emails store staff about %s orders%s; staging would email them too", joinAnd(kinds), sites(siteCount)),
		Fix:     "Set these emails to off in WooCommerce > Settings > Emails in the copy, or route mail to a catcher such as Mailpit",
	})
}

// recipientSettings finds plugin settings named for a recipient that hold
// an email address, such as an email verification plugin's admin address.
func (e *env) recipientSettings(prefixes []string) {
	found, siteCount := 0, 0
	atLeast := false
	var table string
	examples := map[string]bool{}
	for _, p := range prefixes {
		opts := p + "options"
		t := e.table(opts)
		if t == nil || !t.KeyIndex("option_name").Found {
			if t != nil {
				e.warn(fmt.Sprintf("skipped the recipient settings of %s: no index on option_name", opts))
			}
			continue
		}
		// Names first, from the index alone; then the values of those rows.
		rows, err := e.rows("SELECT option_name FROM "+sample.QuoteIdent(opts)+" WHERE option_name LIKE ? LIMIT 50", "%recipient%")
		if err != nil {
			e.warn(fmt.Sprintf("could not read the recipient settings of %s", opts))
			continue
		}
		atLeast = atLeast || len(rows) == 50
		var names []string
		for _, r := range rows {
			names = append(names, r[0])
		}
		n := 0
		for name, v := range e.options(opts, "option_name", "option_value", names) {
			if detect.HasEmail(v) {
				n++
				examples[detect.ShowKey(name)] = true
			}
		}
		if n > 0 {
			found += n
			siteCount++
			if table == "" {
				table = opts
			}
		}
	}
	if found == 0 {
		return
	}
	shown := make([]string, 0, len(examples))
	for name := range examples {
		shown = append(shown, name)
	}
	sort.Strings(shown)
	shown = shown[:min(len(shown), 3)]
	most := ""
	if atLeast {
		most = "at least "
	}
	e.sideEffect(model.SideEffect{
		Platform: wp, Kind: "email", Table: table, Severity: model.SeverityMedium, Count: int64(found),
		Summary: fmt.Sprintf("%s%s%s %s notification emails to staff addresses (for example %s)",
			most, count(found, "plugin setting", "plugin settings"), sites(siteCount), verb(found, "sends", "send"), strings.Join(shown, ", ")),
		Fix: "Point these settings at a test address, or route mail to a catcher such as Mailpit, in the copy",
	})
}

// contactForm7 counts the published Contact Form 7 forms that send mail,
// leaving out those in demo mode or set to skip mail.
func (e *env) contactForm7(prefixes []string) {
	total, siteCount := 0, 0
	var table string
	for _, p := range prefixes {
		posts, meta := p+"posts", p+"postmeta"
		pt, mt := e.table(posts), e.table(meta)
		if pt == nil || mt == nil || !e.has(posts, "post_type", "post_status") || !e.has(meta, "post_id", "meta_key", "meta_value") {
			continue
		}
		if !pt.KeyIndex("post_type").Found || !mt.KeyIndex("post_id").Found {
			e.warn(fmt.Sprintf("skipped the Contact Form 7 check of %s: no index on post_type or post_id", posts))
			continue
		}
		q := "SELECT COUNT(DISTINCT p.ID) FROM " + sample.QuoteIdent(posts) + " p JOIN " + sample.QuoteIdent(meta) +
			" m ON m.post_id = p.ID AND m.meta_key = '_mail' WHERE p.post_type = 'wpcf7_contact_form' AND p.post_status = 'publish'" +
			" AND NOT EXISTS (SELECT 1 FROM " + sample.QuoteIdent(meta) + " a WHERE a.post_id = p.ID AND a.meta_key = '_additional_settings'" +
			" AND (a.meta_value LIKE '%demo_mode: on%' OR a.meta_value LIKE '%skip_mail: on%'))"
		n, err := e.count(q)
		if err != nil {
			e.warn(fmt.Sprintf("could not count the Contact Form 7 forms of %s", posts))
			continue
		}
		if n > 0 {
			total += int(n)
			siteCount++
			if table == "" {
				table = meta
			}
		}
	}
	if total == 0 {
		return
	}
	e.sideEffect(model.SideEffect{
		Platform: wp, Kind: "email", Table: table, Item: "_mail", Severity: model.SeverityMedium, Count: int64(total),
		Summary: fmt.Sprintf("%s%s %s", count(total, "Contact Form 7 form", "Contact Form 7 forms"), sites(siteCount),
			verb(total, "emails its submissions to the addresses in its settings", "email their submissions to the addresses in their settings")),
		Fix: "Route mail to a catcher such as Mailpit in the copy, or add demo_mode: on to each form's Additional Settings",
	})
}

// membershipEmails counts the WooCommerce Memberships emails that are on.
// They go to members on a schedule, for example when a membership ends.
func (e *env) membershipEmails(shops []string) {
	total, siteCount := 0, 0
	var table string
	for _, p := range shops {
		opts := p + "options"
		t := e.table(opts)
		if t == nil || !t.KeyIndex("option_name").Found {
			if t != nil {
				e.warn(fmt.Sprintf("skipped the WooCommerce Memberships emails of %s: no index on option_name", opts))
			}
			continue
		}
		rows, err := e.rows("SELECT option_name, LEFT(option_value, 65535) FROM "+sample.QuoteIdent(opts)+
			" WHERE option_name LIKE ? ESCAPE '!' LIMIT 50", "woocommerce!_wc!_memberships!_%!_settings")
		if err != nil {
			e.warn(fmt.Sprintf("could not read the WooCommerce Memberships emails of %s", opts))
			continue
		}
		n := 0
		for _, r := range rows {
			if yes(detect.Flatten(r[1])["enabled"]) {
				n++
			}
		}
		if n > 0 {
			total += n
			siteCount++
			if table == "" {
				table = opts
			}
		}
	}
	if total == 0 {
		return
	}
	e.sideEffect(model.SideEffect{
		Platform: wc, Kind: "email", Table: table, Severity: model.SeverityHigh, Count: int64(total),
		Summary: fmt.Sprintf("%s %s enabled%s; staging would send %s to members, for example when a membership ends",
			count(total, "WooCommerce Memberships email", "WooCommerce Memberships emails"), verb(total, "is", "are"),
			sites(siteCount), verb(total, "it", "them")),
		Fix: "Turn these emails off in WooCommerce > Settings > Emails in the copy, or route mail to a catcher such as Mailpit",
	})
}

// Plugins that act for the store through its Jetpack connection.
var connectedPlugins = []string{"woocommerce-services/", "woocommerce-shipping/", "woocommerce-tax/", "woocommerce-payments/"}

// connections reports the Jetpack and WooCommerce.com connections a copy
// keeps: through them, services such as WooCommerce Shipping would treat
// the copy as the live store.
func (e *env) connections(prefixes []string, base string, shops []string) {
	jetpack, wooCom, services := false, false, false
	siteCount := 0
	var table string
	network := e.options(base+"sitemeta", "meta_key", "meta_value", []string{"active_sitewide_plugins"})["active_sitewide_plugins"]
	for _, p := range prefixes {
		opts := e.options(p+"options", "option_name", "option_value",
			[]string{"jetpack_private_options", "woocommerce_helper_data", "active_plugins"})
		j := detect.Flatten(opts["jetpack_private_options"])["blog_token"] != ""
		w := detect.Flatten(opts["woocommerce_helper_data"])["auth.access_token"] != ""
		if !j && !w {
			continue
		}
		jetpack, wooCom = jetpack || j, wooCom || w
		siteCount++
		if table == "" {
			table = p + "options"
		}
		for _, slug := range connectedPlugins {
			if strings.Contains(opts["active_plugins"], slug) || strings.Contains(network, slug) {
				services = true
			}
		}
	}
	if siteCount == 0 {
		return
	}
	var what []string
	if jetpack {
		what = append(what, "Jetpack")
	}
	if wooCom {
		what = append(what, "WooCommerce.com")
	}
	platform, sev := wp, model.SeverityMedium
	if len(shops) > 0 {
		platform = wc
	}
	summary := fmt.Sprintf("The copy keeps the live site's %s connection%s; connected services would act for the live site",
		joinAnd(what), sites(siteCount))
	if services {
		sev = model.SeverityHigh
		summary += ", and WooCommerce Shipping, Tax or Payments are active"
	}
	e.sideEffect(model.SideEffect{
		Platform: platform, Kind: "connection", Table: table, Severity: sev, Summary: summary,
		Fix: "Disconnect the copy: delete the blog token in jetpack_private_options and the auth entry in woocommerce_helper_data, " +
			"or define JETPACK_STAGING_MODE in its wp-config.php",
	})
}

// networkMail reports mail plugins configured for a whole network, whose
// settings live in wp_sitemeta.
func (e *env) networkMail(base string) {
	t := base + "sitemeta"
	if !e.has(t, "meta_key", "meta_value") {
		return
	}
	keys := make([]string, len(mailPlugins))
	for i, m := range mailPlugins {
		keys[i] = m.option
	}
	opts := e.options(t, "meta_key", "meta_value", keys)
	for _, m := range mailPlugins {
		raw, ok := opts[m.option]
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		e.sideEffect(model.SideEffect{
			Platform: wp, Kind: "email", Table: t, Item: m.option, Severity: model.SeverityHigh,
			Summary: "Outgoing email of the whole network is sent through " + m.label,
			Fix:     "Point the mailer at a mail catcher such as Mailpit, or turn it off, in the copy",
		})
		if meta := e.res.Meta[t]; meta != nil {
			meta.Probe = append(meta.Probe, m.option)
		}
	}
}

// topHooks renders the most common hooks, "hook (12), other (3)", with
// names that could hold data templated or hidden.
func topHooks(counts map[string]int, n int) string {
	type hc struct {
		hook  string
		count int
	}
	var list []hc
	for h, c := range counts {
		list = append(list, hc{h, c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].hook < list[j].hook
	})
	var parts []string
	for i, x := range list {
		if i == n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", detect.ShowKey(x.hook), x.count))
	}
	return strings.Join(parts, ", ")
}

// joinAnd renders "a", "a and b" or "a, b and c".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// count renders "1 form" or "3 forms".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// verb picks the singular or plural form for n.
func verb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
