package detect

import (
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// NameMatch is what a column name, meta key or JSON key says about its data.
type NameMatch struct {
	Category model.Category
	Words    string         // the words that matched, e.g. "first name"
	Severity model.Severity // zero means the category default
	Note     string
	// Password marks a name that says a password is stored here: values
	// that aren't hashes are then plain text or reversible encryption.
	Password bool
	// Messages marks text written between people, such as private
	// messages and notifications.
	Messages bool
}

type nameRule struct {
	cat      model.Category
	alts     [][]string // any one of these word sequences must appear in order
	types    typeClass
	exclude  map[string]bool
	tableCtx map[string]bool // for bare words: the table or parent key must suggest people
	exact    bool            // the name must be exactly the alternative
	last     bool            // the alternative must end the name
	headNoun bool            // the context's head noun must be a people word
	msgs     bool            // the context must be about messages between people
	// after holds words that rule a name out only after the alternative:
	// password_field is a form's, field_wifi_password_value a password.
	after map[string]bool
	// ctxExclude holds words of the table or parent keys that rule a name out.
	ctxExclude map[string]bool
	// ctxPrefix lets a context word that starts with a tableCtx word count,
	// for tables named with run-together words.
	ctxPrefix bool
	// keepOut keeps the rule's words out of ruleWords, so the splitter,
	// the key-shape guard and labels don't learn them.
	keepOut bool
	sev     model.Severity
	note    string
}

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

func rule(cat model.Category, types typeClass, alts, exclude string) nameRule {
	r := nameRule{cat: cat, types: types, exclude: words(exclude)}
	for _, a := range strings.Split(alts, "|") {
		if f := strings.Fields(a); len(f) > 0 {
			r.alts = append(r.alts, f)
		}
	}
	return r
}

// Words that turn a column into a flag, counter or setting about the data
// rather than the data itself: email_enabled, phone_count, name_format.
var globalExclude = words("is has flag flags enabled disabled enable disable count cnt total length len size " +
	"limit template templates format formats regex pattern placeholder label labels required visible hidden " +
	"show allow allowed can should exists")

// Words that make an address word name something other than a postal
// address: network and memory addresses, wallets, address books.
const addressExclude = "ip mac email mail wallet contract id ids type types book verified validation valid same default " +
	"hash bitcoin eth url web host server bind listen proxy forwarded remote node peer memory pointer offset register endpoint"

// Words naming tables (or parent JSON keys) that hold people.
var peopleWords = words("user users customer customers member members person persons people contact contacts " +
	"employee employees author authors subscriber subscribers client clients patient patients admin admins " +
	"profile profiles lead leads recipient recipients guest guests staff student students applicant applicants " +
	"candidate candidates owner owners teacher teachers driver drivers buyer buyers seller sellers billing shipping " +
	"sender receiver signer attendee attendees participant participants volunteer volunteers donor donors grid")

// Words of a table, or of the keys above a path, whose last mention says
// what a bare name names: a person (peopleWords), or a thing such as a
// group or a role. Container words say neither and are skipped.
var (
	thingWords = words("group groups role roles type types level levels category categories tag tags status " +
		"permission permissions plan plans product products package packages list lists segment segments tier tiers " +
		"rank ranks title titles template templates rule rules badge badges award awards department departments " +
		"team teams project projects event events plugin plugins extension extensions spec specs widget widgets " +
		"module modules theme themes item items action actions notification notifications company companies " +
		"organization organizations organisation organisations business businesses brand brands store stores shop shops")
	containerWords = words("field fields setting settings option options attribute attributes property properties " +
		"meta metadata data info details extra custom values")
)

// peopleHead reports whether the head noun of a context is a people word:
// the last word that is a people word or a thing word, skipping container
// words. users.name names a person; user_roles.name and the path
// user.groups[].name name things.
func peopleHead(ctx []string) bool {
	for i := len(ctx) - 1; i >= 0; i-- {
		w := ctx[i]
		switch {
		case containerWords[w]:
		case peopleWords[w]:
			return true
		case thingWords[w]:
			return false
		}
	}
	return false
}

// Words that make text a message between people, and pm, which does only
// beside a people or message word (WP Project Manager's wp_pm_tasks isn't).
var (
	messageWords = words("message messages msg msgs privmsgs privatemessages pmtext conversation conversations " +
		"inbox notification notifications notify mail mails ticket tickets chat chats shout shouts shoutbox")
	pmWords = words("pm pms")
)

// msgThings head a table, or the keys above a path, of things that belong
// to messages but aren't written between people: chat_rooms, ticket_types,
// message_folders.
var msgThings = words("type types status statuses category categories priority priorities folder folders " +
	"room rooms channel channels label labels tag tags group groups")

// headWord returns the last word of a context that isn't a number.
func headWord(ctx []string) string {
	for i := len(ctx) - 1; i >= 0; i-- {
		if !isDigits(ctx[i]) {
			return ctx[i]
		}
	}
	return ""
}

// aboutMessages reports whether a name or its context is about messages
// between people.
func aboutMessages(tokens, ctx []string) bool {
	all := append(append([]string(nil), ctx...), tokens...)
	return anyIn(all, messageWords) || (anyIn(all, pmWords) && anyIn(all, peopleWords))
}

// passwordWords reports whether a matched alternative names a password.
func passwordWords(alt []string) bool {
	for _, w := range alt {
		switch w {
		case "pass", "password", "passwords", "passphrase", "pw":
			return true
		}
	}
	return false
}

// PeopleWord reports whether a word names people, as users or members do.
func PeopleWord(w string) bool { return peopleWords[w] }

var nameRules = buildRules()

func buildRules() []nameRule {
	const timeWords = "at date time on expires expire expiry expired created updated changed modified sent"
	const userExclude = "attempts " + timeWords + " failed last first ip type url id method provider token key redirect " +
		"page form history after before characters chars charset"
	// Words that describe passwords rather than hold one: how they are
	// hashed, ruled and timed; and, after the password word, who set them
	// and how a page or form shows them (password_page, but page_password).
	const passwordAbout = "type types mode method scheme driver hasher hashing cipher complexity rule rules requirement " +
		"requirements level salt salts pepper iv nonce timestamp ts epoch age timeout ttl duration interval iterations " +
		"rounds cost memory"
	const passwordShown = "page slug protection by color colour background font selector input field class style width " +
		"height icon button"
	paymentWords := words("paypal ipn payment payments transaction transactions txn order orders donation donations " +
		"invoice invoices checkout")
	serviceWords := words("smtp mail ftp sftp ssh db database proxy imap")
	pwContext := words("login auth password credential credentials account accounts")
	accountWords := words("account accounts login logins")
	for w := range peopleWords {
		pwContext[w], accountWords[w] = true, true
	}
	rules := []nameRule{
		func() nameRule {
			r := rule(model.CatPasswordHash, tStr|tBin,
				"password|passwords|user pass|pass hash|hashed pass|password hash|encrypted password|pass word",
				"reset token changed change "+timeWords+" policy hint lifetime attempts failures failure strength algo algorithm requested "+
					"nag generate endpoint lost "+passwordAbout)
			r.after = words(passwordShown)
			return r
		}(),
		rule(model.CatSecret, tStr|tBin|tJSON,
			"secret|secrets|api key|access key|secret key|private key|client secret|consumer secret|consumer key|"+
				"auth key|access token|refresh token|auth token|remember token|reset token|rp token|activation key|"+
				"session token|session tokens|verification token|api token|bearer token|webhook secret|signing secret|"+
				"two factor secret|two factor recovery codes|recovery codes|recovery keys|otp secret|totp secret|mfa secret|"+
				"passphrase|credentials|credential|license key|licence key|token|tokens|salt|smtp pass|mail pass|"+
				"mailserver pass|email pass|app password|application password|login key|api signature|"+
				"ftp pass|sftp pass|ssh pass|db pass|database pass|proxy pass|imap pass|pop pass|api pass|"+
				"twitter ckey|twitter csecret|twitter asecret|twitter atoken",
			"count used limit type name "+timeWords+" version enabled ttl lifetime length scope scopes abilities"),
		// pass alone: a person's password (admin.pass), or a service's
		// (smtp.pass), by the words around it. People, accounts and logins
		// come first: mail and FTP servers keep their users' hashes in tables
		// such as ftp_users or smtp_logins, and a service named above a path
		// still makes its pass a secret when the values are judged. A season
		// or battle pass is neither.
		func() nameRule {
			r := rule(model.CatPasswordHash, tStr|tBin, "pass", "")
			r.exact, r.tableCtx = true, accountWords
			return r
		}(),
		func() nameRule {
			r := rule(model.CatSecret, tStr|tBin, "pass", "")
			r.exact, r.tableCtx = true, serviceWords
			return r
		}(),
		func() nameRule {
			r := rule(model.CatPasswordHash, tStr|tBin,
				"admin pass|user pass|client pass|member pass|account pass|login pass|root pass|customer pass", "")
			r.last = true
			return r
		}(),
		func() nameRule {
			// A POST log's newpass and oldpass; a game's current_pass isn't one.
			r := rule(model.CatPasswordHash, tStr|tBin, "new pass|old pass|current pass", "")
			r.last, r.tableCtx = true, pwContext
			return r
		}(),
		rule(model.CatCardNumber, tStr|tBigInt|tNum,
			"card number|cc number|credit card|card num|cc num|pan|ccnum|cardnum|card no|credit card number",
			"last 4 four type brand expiry exp month year holder owner name token hash masked mask bin issuer "+
				"country ss enc"),
		func() nameRule {
			// Storing a card's security code at all breaks PCI DSS.
			r := rule(model.CatCardMeta, tStr|tSmallInt, "cvv|cvc|cvv2|cvc2|card security code|card code", "")
			r.sev = model.SeverityHigh
			r.note = "card security codes must never be stored (PCI DSS)"
			return r
		}(),
		rule(model.CatCardMeta, tStr|tSmallInt|tBigInt|tEnum,
			"last 4|last four|cc last|card last|cc exp|card exp|card expiry|exp month|exp year|cc type|card type|"+
				"card brand|card bin",
			""),
		rule(model.CatEmail, tStr,
			"email|emails|e mail|mail address",
			"sent send verified verify verification confirmed confirm status type subject body content setting "+
				"settings opt optin notify notification notifications domain valid invalid bounced bounce unsubscribed "+
				"subscribed sync synced "+timeWords+" id ids hash hashed token queue log error errors attempts "+
				"frequency preference preferences consent agreed accepted marketing color colour background image header footer "+
				"heading text"),
		rule(model.CatPhone, tStr|tBigInt|tNum,
			"phone|phones|telephone|tel|mobile|fax|msisdn|cell phone|phone number|mobile number|whatsapp|sms number",
			"verified verify verification confirmed type code country prefix ext extension "+timeWords+
				" status notification notifications consent theme app device os version model brand optin opt template "+
				"score scores pagescore interactive speed pagespeed menu breakpoint layout width height"),
		rule(model.CatIPAddress, tStr|tInt|tBin|tInet,
			"ip|ip address|ipv4|ipv6|remote addr|remote ip|client ip|x forwarded for|forwarded for|real ip|"+
				"src addr|source addr|client addr|real addr|origin addr|local addr|dst addr|dest addr",
			"country city region location geo whitelist allowlist blacklist blocklist range ranges version type "+
				"lookup rule rules setting settings restriction restrictions"),
		// Hardware identifiers. A bare device_id usually points at a devices
		// table, as user_id points at users, so it isn't one of them.
		rule(model.CatDeviceID, tStr,
			"hwid|hardware id|machine id|device fingerprint|udid|imei|android id|advertising id",
			"type name model os version status "+timeWords),
		rule(model.CatDeviceID, tBigInt, "imei", "type name model os version status "+timeWords),
		rule(model.CatUserAgent, tStr,
			"user agent|http user agent|browser agent|ua string", "type"),
		rule(model.CatWebsite, tStr,
			"user url|website|web site|homepage|home page|author url|personal url|profile url|blog url|"+
				"twitter|facebook|linkedin|instagram",
			"id type enabled title"),
		rule(model.CatDateOfBirth, tStr|tDate|tSmallInt,
			"dob|birthday|birth date|date of birth|birth day|born|birth year|date birth|bday|birth month",
			"reminder email sent notification coupon discount"),
		rule(model.CatNationalID, tStr,
			"ssn|social security|national id|national insurance|nin|nino|tax id|tax vat|vat|vat id|vat number|"+
				"tax number|tax code|fiscal code|codice fiscale|passport|passport number|id number|identity number|"+
				"id card|identity card|driver license|drivers license|driving licence|driving license|afm|amka|cpf|cnpj|"+
				"pesel|bsn|nif|nie",
			"type country expiry expires issued verified status exempt class rate rates amount percent included "+
				"inclusive display request requested valid"),
		rule(model.CatBankAccount, tStr|tBigInt,
			"iban|bank account|bank account number|account number|routing number|sort code",
			"type name holder verified country currency status"),
		rule(model.CatPaymentToken, tStr,
			"payment token|gateway token|vault token|card token|stripe id|stripe customer id|stripe customer|"+
				"stripe source id|braintree id|braintree customer id|customer token|payment method token|"+
				"payment method id|billing agreement id|pm id",
			"type "+timeWords),
		// An address word with a component word is that component (city,
		// postcode, country) or not an address at all (status, request);
		// a street word stays a street address (street_name, street_code).
		rule(model.CatAddress, tStr,
			"address|addresses|addr|address line",
			addressExclude+" country city state zip postcode region province county status code name request"),
		rule(model.CatAddress, tStr,
			"street|street address|house number|apartment|apt", addressExclude),
		func() nameRule {
			// line1 and line2 are address lines only inside an address.
			r := rule(model.CatAddress, tStr, "line 1|line 2|line 3", "id ids type item items")
			r.tableCtx = words("address addresses shipping billing delivery postal mailing")
			return r
		}(),
		rule(model.CatPostcode, tStr|tSmallInt,
			"postcode|post code|postal code|zip|zip code|plz|postal",
			"file path url archive download compressed compression type id ids range from to"),
		rule(model.CatCity, tStr,
			"city|town|locality|suburb", "id ids code type list tax"),
		rule(model.CatRegion, tStr,
			"region|province|county|billing state|shipping state|address state|state province",
			"id ids type tax rate rates"),
		rule(model.CatCountry, tStr|tEnum,
			"country|country code|country id|nationality|citizenship",
			"ids phone calling dial currency tax rate allowed specific restrict restricted list type"),
		rule(model.CatGeo, tStr|tNum|tGeo|tJSON,
			"latitude|longitude|lat|lng|lon|geo|geolocation|geo location|coordinates|coords|gps",
			"id ids type radius count zone zones tax code"),
		rule(model.CatGeo, tGeo, "location|geo point|geopoint|position", "id ids type"),
		rule(model.CatPersonName, tStr,
			"first name|last name|middle name|full name|given name|family name|surname|maiden name|fname|lname|"+
				"display name|nick name|real name|screen name|contact name|customer name|billing name|shipping name|"+
				"recipient name|receiver name|sender name|author name|card holder|cardholder name|cc owner|card owner|"+
				"account holder|comment author|contact person|patient name|guest name|attendee name",
			"id ids field order type url slug email ip agent"),
		// The name on an address: always on a shipping or billing one, and
		// on a bare address_name only in payment data such as PayPal IPN,
		// since elsewhere it may be a label such as "Home".
		rule(model.CatPersonName, tStr,
			"billing address name|shipping address name|delivery address name|recipient address name", "id ids type"),
		func() nameRule {
			// A table named with one run-together word, such as paypalsales, is payment data too.
			r := rule(model.CatPersonName, tStr, "address name", "id ids type")
			r.tableCtx, r.ctxPrefix = paymentWords, true
			return r
		}(),
		func() nameRule {
			r := rule(model.CatPersonName, tStr, "name|names", "")
			r.exact, r.headNoun = true, true
			return r
		}(),
		rule(model.CatUsername, tStr,
			"user name|user login|login name|nice name|account name|summoner name|player name|gamer tag|gamertag",
			userExclude),
		func() nameRule {
			// IPB's members_seo_name is a slug of the display name.
			r := rule(model.CatUsername, tStr, "seo name", userExclude)
			r.tableCtx = peopleWords
			return r
		}(),
		func() nameRule {
			// A bare "login" is a username only at the end, as in
			// smtp_login; login_align and login_btn_word set up a form.
			r := rule(model.CatUsername, tStr, "login", userExclude)
			r.last = true
			return r
		}(),
		rule(model.CatGender, tStr|tSmallInt|tEnum, "gender|sex", "options list"),
		rule(model.CatCompany, tStr,
			"company|company name|organisation|organization|employer|business name|org name",
			"id ids type code number vat tax registration logo url policy privacy tos terms signature note notes"),
		rule(model.CatSessionData, tStr|tBin|tJSON,
			"session data|session value|session payload|session",
			"id ids key "+timeWords+" name lifetime handler"),
		rule(model.CatFreeText, tStr,
			"comment|comments|customer note|note|notes|message|messages|remarks|feedback|review text|review|"+
				"inquiry|enquiry|bio|biography|about me|signature",
			"id ids type status "+timeWords+" notify notification approved parent karma subject"),
		func() nameRule {
			// The text of messages between people: private messages,
			// notifications, mail and tickets, but not their templates.
			// Vendor news feeds (Magento's adminnotification_inbox,
			// AbanteCart's ant_messages), menus and notification specs
			// aren't written by people to people either.
			// Nor are the types, statuses and categories of tickets, or a
			// message's content_type, post_status or msg_post_key.
			const notWritten = "template templates form forms setting settings option options config language languages " +
				"lang translation translations phrase phrases label labels newsletter newsletters campaign campaigns " +
				"bulk mass adminnotification ant menu menus nav spec specs"
			r := rule(model.CatFreeText, tStr, "text|title|subject|body|content|post",
				notWritten+" id ids type types status key "+timeWords)
			r.msgs, r.ctxExclude = true, words(notWritten+" type types status statuses category categories")
			return r
		}(),
		// Last, so "recipient name" stays a name and "recipient message" free text.
		rule(model.CatEmail, tStr, "recipient|recipients", "name names type types id ids count role roles"),
		// After every other rule, so a name one of them knows keeps its
		// category (ip_webhook, email_webhook). A webhook's URL may carry a
		// token, or be the site's own callback, so it's medium.
		func() nameRule {
			r := rule(model.CatSecret, tStr|tBin|tJSON, "webhook|webhooks|webhook url|webhook urls|webhook uri|hook url",
				"use send sent trigger triggered last")
			r.last, r.keepOut, r.sev = true, true, model.SeverityMedium
			return r
		}(),
		func() nameRule {
			// Paddle Classic's vendor_auth_code, and PHP_AUTH_PW in logged
			// $_SERVER arrays, judged as a password.
			r := rule(model.CatSecret, tStr|tBin|tJSON, "vendor auth code|auth pw", "use send sent trigger triggered last")
			r.last, r.keepOut = true, true
			return r
		}(),
	}
	return rules
}

// match returns the longest alternative found in tokens, so "country id"
// wins over "country" for country_id.
func (r *nameRule) match(tokens []string) []string {
	var best []string
	for _, alt := range r.alts {
		if r.exact && len(alt) != len(tokens) {
			continue
		}
		if r.last {
			end := len(tokens)
			for end > 0 && isDigits(tokens[end-1]) {
				end-- // smtp_login_2 still ends in login
			}
			if len(alt) > end || !hasSeq(tokens[end-len(alt):end], alt) {
				continue
			}
		}
		if len(alt) > len(best) && hasSeq(tokens, alt) {
			best = alt
		}
	}
	return best
}

func hasSeq(tokens, seq []string) bool { return seqEnd(tokens, seq) >= 0 }

// seqEnd returns the index just past the first place seq appears in
// tokens, or -1.
func seqEnd(tokens, seq []string) int {
	for i := 0; i+len(seq) <= len(tokens); i++ {
		ok := true
		for j := range seq {
			if tokens[i+j] != seq[j] {
				ok = false
				break
			}
		}
		if ok {
			return i + len(seq)
		}
	}
	return -1
}

func anyIn(tokens []string, set map[string]bool) bool {
	for _, t := range tokens {
		if set[t] {
			return true
		}
	}
	return false
}

// anyPrefix reports whether a token starts with one of the words in set.
func anyPrefix(tokens []string, set map[string]bool) bool {
	for _, t := range tokens {
		for w := range set {
			if len(t) > len(w) && strings.HasPrefix(t, w) {
				return true
			}
		}
	}
	return false
}

var idWords = words("id ids uuid guid")

// MatchName applies the naming rules to the words of a column name or key.
// ctx holds the words of the table name (or parent JSON keys); tc is the
// column's type class. It returns nil when the name says nothing.
func MatchName(tokens, ctx []string, tc typeClass) *NameMatch {
	if len(tokens) == 0 || anyIn(tokens, globalExclude) {
		return nil
	}
	idLike := idWords[tokens[len(tokens)-1]]
	for i := range nameRules {
		r := &nameRules[i]
		if r.types&tc == 0 || anyIn(tokens, r.exclude) || anyIn(ctx, r.ctxExclude) {
			continue
		}
		alt := r.match(tokens)
		if alt == nil || (r.after != nil && anyIn(tokens[seqEnd(tokens, alt):], r.after)) {
			continue
		}
		if idLike && !idWords[alt[len(alt)-1]] {
			if tc&tInt != 0 {
				return nil // an integer *_id column is a reference, not data
			}
			continue
		}
		if r.tableCtx != nil && !anyIn(ctx, r.tableCtx) && !(r.ctxPrefix && anyPrefix(ctx, r.tableCtx)) {
			continue
		}
		if (r.headNoun && !peopleHead(ctx)) || (r.msgs && (!aboutMessages(tokens, ctx) || msgThings[headWord(ctx)])) {
			continue
		}
		return &NameMatch{Category: r.cat, Words: strings.Join(alt, " "), Severity: r.sev, Note: r.note,
			Password: passwordWords(alt), Messages: r.msgs}
	}
	return nil
}
