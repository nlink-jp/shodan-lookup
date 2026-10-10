package engine

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// The wire types decode only what the projection uses, through decodeLoose
// (loose.go): a value of an unexpected type is left out, not fatal. Pointers
// mark fields whose absence must stay distinguishable from a zero value;
// everything else is reachable through --raw.

type wireHost struct {
	IPStr       string        `json:"ip_str"`
	Org         *text         `json:"org"`
	ISP         *text         `json:"isp"`
	ASN         *text         `json:"asn"`
	CountryCode *text         `json:"country_code"`
	City        *text         `json:"city"`
	Hostnames   []string      `json:"hostnames"`
	Domains     []string      `json:"domains"`
	OS          *text         `json:"os"`
	Tags        []string      `json:"tags"`
	LastUpdate  string        `json:"last_update"`
	Ports       []int         `json:"ports"`
	Vulns       []string      `json:"vulns"`
	Data        []wireService `json:"data"`
}

type wireService struct {
	Port      int                     `json:"port"`
	Transport string                  `json:"transport"`
	Timestamp string                  `json:"timestamp"`
	Product   *text                   `json:"product"`
	Version   *text                   `json:"version"`
	CPE23     []string                `json:"cpe23"`
	Data      string                  `json:"data"`
	Tags      []string                `json:"tags"`
	Shodan    struct{ Module string } `json:"_shodan"`
	HTTP      *wireHTTP               `json:"http"`
	SSL       *wireSSL                `json:"ssl"`
	Vulns     map[string]wireVuln     `json:"vulns"`
}

type wireHTTP struct {
	Status   *int                       `json:"status"`
	Title    *text                      `json:"title"`
	Server   *text                      `json:"server"`
	Location *text                      `json:"location"`
	HTML     *text                      `json:"html"`
	Headers  map[string]json.RawMessage `json:"headers"`
	Favicon  *struct {
		Hash *int64 `json:"hash"`
	} `json:"favicon"`
}

type wireSSL struct {
	Cert     json.RawMessage `json:"cert"`
	Chain    []string        `json:"chain"`
	Versions []string        `json:"versions"`
}

// wireCert is the part of ssl.cert the projection reads; the whole object is
// the ssl_cert section.
type wireCert struct {
	Subject     map[string]json.RawMessage `json:"subject"`
	Issuer      map[string]json.RawMessage `json:"issuer"`
	Issued      string                     `json:"issued"`
	Expires     string                     `json:"expires"`
	Fingerprint struct {
		SHA1   string `json:"sha1"`
		SHA256 string `json:"sha256"`
	} `json:"fingerprint"`
}

type wireVuln struct {
	CVSS        *float64 `json:"cvss"`
	CVSSVersion *float64 `json:"cvss_version"`
	EPSS        *float64 `json:"epss"`
	Verified    bool     `json:"verified"`
	Summary     string   `json:"summary"`
	References  []string `json:"references"`
}

// shodanTime reads Shodan's banner timestamp. It carries no zone suffix; it
// is UTC (measured: the newest observation fell 2–30 minutes before the
// response's GMT Date header, 3 of 3).
func shodanTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// certTime reads a certificate date as Shodan writes it: 20261221192001Z.
func certTime(s string) (time.Time, bool) {
	t, err := time.ParseInLocation("20060102150405Z", s, time.UTC)
	return t, err == nil
}

// nameField returns one attribute of a certificate name (CN, O, …) when it is
// a string, and "" otherwise.
func nameField(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ", ")
	}
	return ""
}

// headerValue renders an HTTP header value, which Shodan sends as a string
// and occasionally as a list.
func headerValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ", ")
	}
	return string(raw)
}

// text is a scalar Shodan sends as a string without holding it to one type:
// asn arrives as "AS2497" and as 2497 within one host record (measured,
// 2026-10-10). A number is read as its JSON text, so the value is kept
// rather than left out by decodeLoose; anything else is still left out.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*t = text(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("not a string or a number")
	}
	*t = text(n)
	return nil
}

func str(p *text) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

// asName writes an AS number as Shodan's string form does, AS2497, whichever
// of the two forms the record used.
func asName(s string) string {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return s
	}
	return "AS" + s
}
