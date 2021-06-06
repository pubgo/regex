package regex

import "regexp"

func pattern(p string) *Regex {
	return &Regex{Build: func() *regexp.Regexp { return regexp.MustCompile(p) }}
}

func init() {
	Register("date", pattern(datePattern))
	Register("time", pattern(timePattern))
	Register("phone", pattern(phonePattern))
	Register("phone_exts", pattern(phonesWithExtsPattern))
	Register("link", pattern(linkPattern))
	Register("email", pattern(emailPattern))
	Register("ipv4", pattern(ipv4Pattern))
	Register("ipv6", pattern(ipv6Pattern))
	Register("ip", pattern(ipPattern))
	Register("not_known_port", pattern(notKnownPortPattern))
	Register("price", pattern(pricePattern))
	Register("hex_color", pattern(hexColorPattern))
	Register("credit_card", pattern(creditCardPattern))
	Register("visa_credit_card", pattern(vISACreditCardPattern))
	Register("mc_credit_card", pattern(mcCreditCardPattern))
	Register("btc_address", pattern(btcAddressPattern))
	Register("street_address", pattern(streetAddressPattern))
	Register("zip_code", pattern(zipCodePattern))
	Register("po_box", pattern(poBoxPattern))
	Register("ssn", pattern(ssnPattern))
	Register("md5_hex", pattern(md5HexPattern))
	Register("sha1_hex", pattern(sha1HexPattern))
	Register("sha256_hex", pattern(sha256HexPattern))
	Register("guid", pattern(guidPattern))
	Register("isbn13", pattern(isbn13Pattern))
	Register("isbn10", pattern(isbn10Pattern))
	Register("mac_address", pattern(macAddressPattern))
	Register("iban", pattern(ibanPattern))
	Register("git_repo", pattern(gitRepoPattern))
}

// Regular expression patterns
const (
	datePattern           = `(?i)(?:[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}`
	timePattern           = `(?i)\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?`
	phonePattern          = `(?:(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4,6})|(?:(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4})`
	phonesWithExtsPattern = `(?i)(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?)`
	linkPattern           = `(?:(?:https?:\/\/)?(?:[a-z0-9.\-]+|www|[a-z0-9.\-])[.](?:[^\s()<>]+|\((?:[^\s()<>]+|(?:\([^\s()<>]+\)))*\))+(?:\((?:[^\s()<>]+|(?:\([^\s()<>]+\)))*\)|[^\s!()\[\]{};:\'".,<>?]))`
	emailPattern          = `(?i)([A-Za-z0-9!#$%&'*+\/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)`
	ipv4Pattern           = `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`
	ipv6Pattern           = `(?:(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:))|(?:(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){5}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){4}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,3})|(?:(?::[0-9A-Fa-f]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){3}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,4})|(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){2}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,5})|(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9A-Fa-f]{1,4}:){1}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?::(?:(?:(?::[0-9A-Fa-f]{1,4}){1,7})|(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(?:%.+)?\s*`
	ipPattern             = ipv4Pattern + `|` + ipv6Pattern
	notKnownPortPattern   = `6[0-5]{2}[0-3][0-5]|[1-5][\d]{4}|[2-9][\d]{3}|1[1-9][\d]{2}|10[3-9][\d]|102[4-9]`
	pricePattern          = `[$]\s?[+-]?[0-9]{1,3}(?:(?:,?[0-9]{3}))*(?:\.[0-9]{1,2})?`
	hexColorPattern       = `(?:#?([0-9a-fA-F]{6}|[0-9a-fA-F]{3}))`
	creditCardPattern     = `(?:(?:(?:\d{4}[- ]?){3}\d{4}|\d{15,16}))`
	vISACreditCardPattern = `4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
	mcCreditCardPattern   = `5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
	btcAddressPattern     = `[13][a-km-zA-HJ-NP-Z1-9]{25,34}`
	streetAddressPattern  = `\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?`
	zipCodePattern        = `\b\d{5}(?:[-\s]\d{4})?\b`
	poBoxPattern          = `(?i)P\.? ?O\.? Box \d+`
	ssnPattern            = `(?:\d{3}-\d{2}-\d{4})`
	md5HexPattern         = `[0-9a-fA-F]{32}`
	sha1HexPattern        = `[0-9a-fA-F]{40}`
	sha256HexPattern      = `[0-9a-fA-F]{64}`
	guidPattern           = `[0-9a-fA-F]{8}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{4}-?[a-fA-F0-9]{12}`
	isbn13Pattern         = `(?:[\d]-?){12}[\dxX]`
	isbn10Pattern         = `(?:[\d]-?){9}[\dxX]`
	macAddressPattern     = `(([a-fA-F0-9]{2}[:-]){5}([a-fA-F0-9]{2}))`
	ibanPattern           = `[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z\d]?){0,16}`
	gitRepoPattern        = `((git|ssh|http(s)?)|(git@[\w\.]+))(:(\/\/)?)([\w\.@\:/\-~]+)(\.git)(\/)?`
)

func match(text string, reg string) []string {
	var regex = Get(reg)
	if regex == nil {
		return nil
	}

	return regex.FindAllString(text, -1)
}

// Date finds all date strings
func Date(text string) []string { return match(text, "date") }

// Time finds all time strings
func Time(text string) []string { return match(text, "time") }

// Phones finds all phone numbers
func Phones(text string) []string { return match(text, "phone") }

// PhonesWithExts finds all phone numbers with ext
func PhonesWithExts(text string) []string { return match(text, "phone_exts") }

// Links finds all link strings
func Links(text string) []string { return match(text, "link") }

// Emails finds all email strings
func Emails(text string) []string { return match(text, "email") }

// IPv4s finds all IPv4 addresses
func IPv4s(text string) []string { return match(text, "ipv4") }

// IPv6s finds all IPv6 addresses
func IPv6s(text string) []string { return match(text, "ipv6") }

// IPs finds all IP addresses (both IPv4 and IPv6)
func IPs(text string) []string { return match(text, "ip") }

// NotKnownPorts finds all not-known port numbers
func NotKnownPorts(text string) []string { return match(text, "not_known_port") }

// Prices finds all price strings
func Prices(text string) []string { return match(text, "price") }

// HexColors finds all hex color values
func HexColors(text string) []string { return match(text, "hex_color") }

// CreditCards finds all credit card numbers
func CreditCards(text string) []string { return match(text, "credit_card") }

// BtcAddresses finds all bitcoin addresses
func BtcAddresses(text string) []string { return match(text, "btc_address") }

// StreetAddresses finds all street addresses
func StreetAddresses(text string) []string { return match(text, "street_address") }

// ZipCodes finds all zip codes
func ZipCodes(text string) []string { return match(text, "zip_code") }

// PoBoxes finds all po-box strings
func PoBoxes(text string) []string { return match(text, "po_box") }

// SSNs finds all SSN strings
func SSNs(text string) []string { return match(text, "ssn") }

// MD5Hexes finds all MD5 hex strings
func MD5Hexes(text string) []string { return match(text, "md5_hex") }

// SHA1Hexes finds all SHA1 hex strings
func SHA1Hexes(text string) []string { return match(text, "sha1_hex") }

// SHA256Hexes finds all SHA256 hex strings
func SHA256Hexes(text string) []string { return match(text, "sha256_hex") }

// GUIDs finds all GUID strings
func GUIDs(text string) []string { return match(text, "guid") }

// ISBN13s finds all ISBN13 strings
func ISBN13s(text string) []string { return match(text, "isbn13") }

// ISBN10s finds all ISBN10 strings
func ISBN10s(text string) []string { return match(text, "isbn10") }

// VISACreditCards finds all VISA credit card numbers
func VISACreditCards(text string) []string { return match(text, "visa_credit_card") }

// MCCreditCards finds all MasterCard credit card numbers
func MCCreditCards(text string) []string { return match(text, "mc_credit_card") }

// MACAddresses finds all MAC addresses
func MACAddresses(text string) []string { return match(text, "mac_address") }

// IBANs finds all IBAN strings
func IBANs(text string) []string { return match(text, "iban") }

// GitRepos finds all git repository addresses which have protocol prefix
func GitRepos(text string) []string { return match(text, "git_repo") }
