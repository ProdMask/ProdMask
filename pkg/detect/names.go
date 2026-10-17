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
}

type nameRule struct {
	cat      model.Category
	alts     [][]string // any one of these word sequences must appear in order
	types    typeClass
	exclude  map[string]bool
	tableCtx map[string]bool // for bare words: the table or parent key must suggest people
	exact    bool            // the name must be exactly the alternative
	last     bool            // the alternative must end the name
	sev      model.Severity
	note     string
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

// Words naming tables (or parent JSON keys) that hold people.
var peopleWords = words("user users customer customers member members person persons people contact contacts " +
	"employee employees author authors subscriber subscribers client clients patient patients admin admins " +
	"profile profiles lead leads recipient recipients guest guests staff student students applicant applicants " +
	"candidate candidates owner owners teacher teachers driver drivers buyer buyers seller sellers billing shipping " +
	"sender receiver signer attendee attendees participant participants volunteer volunteers donor donors grid")

var nameRules = buildRules()

func buildRules() []nameRule {
	const timeWords = "at date time on expires expire expiry expired created updated changed modified sent"
	const userExclude = "attempts " + timeWords + " failed last ip type url id method provider token key redirect " +
		"page form history after before"
	rules := []nameRule{
		rule(model.CatPasswordHash, tStr|tBin,
			"password|passwords|user pass|pass hash|hashed pass|password hash|encrypted password|pass word",
			"reset token changed change "+timeWords+" policy hint lifetime attempts failures failure strength algo algorithm requested "+
				"nag generate endpoint lost"),
		rule(model.CatSecret, tStr|tBin|tJSON,
			"secret|secrets|api key|access key|secret key|private key|client secret|consumer secret|consumer key|"+
				"auth key|access token|refresh token|auth token|remember token|reset token|rp token|activation key|"+
				"session token|session tokens|verification token|api token|bearer token|webhook secret|signing secret|"+
				"two factor secret|two factor recovery codes|recovery codes|recovery keys|otp secret|totp secret|mfa secret|"+
				"passphrase|credentials|credential|license key|licence key|token|tokens|salt|smtp pass|mail pass|"+
				"mailserver pass|app password|application password",
			"count used limit type name "+timeWords+" version enabled ttl lifetime length scope scopes abilities"),
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
			"ip|ip address|ipv4|ipv6|remote addr|remote ip|client ip|x forwarded for|forwarded for|real ip",
			"country city region location geo whitelist allowlist blacklist blocklist range ranges version type "+
				"lookup rule rules setting settings restriction restrictions"),
		rule(model.CatUserAgent, tStr,
			"user agent|http user agent|browser agent|ua string", "type"),
		rule(model.CatWebsite, tStr,
			"user url|website|web site|homepage|home page|author url|personal url|profile url|blog url|"+
				"twitter|facebook|linkedin|instagram",
			"id type enabled title"),
		rule(model.CatDateOfBirth, tStr|tDate|tSmallInt,
			"dob|birthday|birth date|date of birth|birth day|born|birth year|date birth",
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
		rule(model.CatAddress, tStr,
			"address|addresses|street|addr|address line|street address|house number|apartment|apt",
			"ip mac email mail wallet contract id ids type types book verified validation valid same default hash "+
				"bitcoin eth url web host server bind listen proxy forwarded remote node peer memory pointer offset "+
				"register endpoint"),
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
		func() nameRule {
			r := rule(model.CatPersonName, tStr, "name|names", "")
			r.exact, r.tableCtx = true, peopleWords
			return r
		}(),
		rule(model.CatUsername, tStr,
			"user name|user login|login name|nice name|account name", userExclude),
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
			"id ids type code number vat tax registration logo url"),
		rule(model.CatSessionData, tStr|tBin|tJSON,
			"session data|session value|session payload|session",
			"id ids key "+timeWords+" name lifetime handler"),
		rule(model.CatFreeText, tStr,
			"comment|comments|customer note|note|notes|message|messages|remarks|feedback|review text|review|"+
				"inquiry|enquiry|bio|biography|about me",
			"id ids type status "+timeWords+" notify notification approved parent karma subject"),
		// Last, so "recipient name" stays a name and "recipient message" free text.
		rule(model.CatEmail, tStr, "recipient|recipients", "name names type types id ids count role roles"),
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

func hasSeq(tokens, seq []string) bool {
	for i := 0; i+len(seq) <= len(tokens); i++ {
		ok := true
		for j := range seq {
			if tokens[i+j] != seq[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func anyIn(tokens []string, set map[string]bool) bool {
	for _, t := range tokens {
		if set[t] {
			return true
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
		if r.types&tc == 0 || anyIn(tokens, r.exclude) {
			continue
		}
		alt := r.match(tokens)
		if alt == nil {
			continue
		}
		if idLike && !idWords[alt[len(alt)-1]] {
			if tc&tInt != 0 {
				return nil // an integer *_id column is a reference, not data
			}
			continue
		}
		if r.tableCtx != nil && !anyIn(ctx, r.tableCtx) {
			continue
		}
		return &NameMatch{Category: r.cat, Words: strings.Join(alt, " "), Severity: r.sev, Note: r.note}
	}
	return nil
}
