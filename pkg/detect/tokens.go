// Package detect decides which columns, meta keys and JSON paths hold
// personal data or secrets, from their names and from sampled values. It
// never keeps or returns the values themselves, only counts.
package detect

import (
	"strings"
	"unicode"
)

// Tokens splits an identifier into lower-case words. It understands
// snake_case, kebab-case, camelCase and digits, and splits a few common
// compounds: "firstname" becomes first, name.
func Tokens(name string) []string {
	var (
		toks []string
		cur  []rune
	)
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, string(cur))
			cur = cur[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case unicode.IsUpper(r):
			if len(cur) > 0 {
				prev := runes[i-1]
				next := rune(0)
				if i+1 < len(runes) {
					next = runes[i+1]
				}
				// fooBar, foo2Bar and the "A" in IPAddress start a new word.
				if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && unicode.IsLower(next)) {
					flush()
				}
			}
			cur = append(cur, unicode.ToLower(r))
		case unicode.IsDigit(r):
			if len(cur) > 0 && !unicode.IsDigit(runes[i-1]) {
				flush()
			}
			cur = append(cur, r)
		case unicode.IsLetter(r):
			if len(cur) > 0 && unicode.IsDigit(runes[i-1]) {
				flush()
			}
			cur = append(cur, unicode.ToLower(r))
		default:
			flush()
		}
	}
	flush()

	out := make([]string, 0, len(toks))
	for _, t := range toks {
		if c, ok := compounds[t]; ok {
			out = append(out, c...)
		} else {
			out = append(out, t)
		}
	}
	return out
}

// compounds are words written without separators that the rules need split.
var compounds = map[string][]string{
	"firstname": {"first", "name"}, "lastname": {"last", "name"}, "middlename": {"middle", "name"},
	"fullname": {"full", "name"}, "givenname": {"given", "name"}, "familyname": {"family", "name"},
	"displayname": {"display", "name"}, "nickname": {"nick", "name"}, "username": {"user", "name"},
	"nicename": {"nice", "name"}, "screenname": {"screen", "name"}, "realname": {"real", "name"},
	"emailaddress": {"email", "address"}, "mailaddress": {"mail", "address"},
	"phonenumber": {"phone", "number"}, "phoneno": {"phone", "number"}, "mobilephone": {"mobile", "phone"},
	"mobilenumber": {"mobile", "number"}, "cellphone": {"cell", "phone"},
	"zipcode": {"zip", "code"}, "postalcode": {"postal", "code"},
	"birthdate": {"birth", "date"}, "dateofbirth": {"date", "of", "birth"},
	"ipaddress": {"ip", "address"}, "ipaddr": {"ip", "address"}, "remoteaddr": {"remote", "addr"},
	"remoteip": {"remote", "ip"}, "clientip": {"client", "ip"}, "useragent": {"user", "agent"},
	"creditcard": {"credit", "card"}, "cardnumber": {"card", "number"}, "ccnumber": {"cc", "number"},
	"apikey": {"api", "key"}, "apisecret": {"api", "secret"}, "accesstoken": {"access", "token"},
	"refreshtoken": {"refresh", "token"}, "authtoken": {"auth", "token"}, "secretkey": {"secret", "key"},
	"privatekey": {"private", "key"}, "clientsecret": {"client", "secret"},
	"passwordhash": {"password", "hash"}, "passwd": {"password"}, "pwd": {"password"},
	"taxvat": {"tax", "vat"}, "vatnumber": {"vat", "number"}, "taxnumber": {"tax", "number"},
	"streetaddress": {"street", "address"}, "housenumber": {"house", "number"},
	"accountnumber": {"account", "number"}, "cardholder": {"card", "holder"},
}

// typeClass groups SQL data types by what they can hold.
type typeClass uint16

const (
	tStr typeClass = 1 << iota
	tSmallInt
	tBigInt
	tNum
	tDate
	tBin
	tInet
	tEnum
	tGeo
	tJSON
	tOther

	tInt typeClass = tSmallInt | tBigInt
)

// classOf maps an information_schema DATA_TYPE to its class.
func classOf(dataType string) typeClass {
	switch strings.ToLower(dataType) {
	case "char", "varchar", "tinytext", "text", "mediumtext", "longtext", "uuid", "nchar", "nvarchar":
		return tStr
	case "json":
		return tStr | tJSON
	case "enum", "set":
		return tEnum
	case "tinyint", "smallint", "mediumint", "int", "integer":
		return tSmallInt
	case "bigint":
		return tBigInt
	case "decimal", "numeric", "float", "double", "real":
		return tNum
	case "date", "datetime", "timestamp", "time", "year":
		return tDate
	case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob":
		return tBin
	case "inet4", "inet6":
		return tInet
	case "geometry", "point", "linestring", "polygon", "multipoint", "multilinestring",
		"multipolygon", "geometrycollection", "geomcollection":
		return tGeo
	}
	return tOther
}
