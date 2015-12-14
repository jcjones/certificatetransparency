package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/certificatetransparency"
)

var (
	inputPath  = flag.String("i", "", "file path to Certificate Transparency log file")
	offsetFlag = flag.Int64("offset", 0, "byte offset to skip to in the file")
	verbose    = flag.Bool("v", false, "verbose output")
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("")
	entryFilePath := *inputPath
	offset := *offsetFlag
	if len(entryFilePath) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	f, err := os.Open(entryFilePath)
	if err != nil {
		log.Fatalf("unable to open %#v: %s", entryFilePath, err)
	}
	if *verbose {
		log.Printf("seeking to %d", offset)
	}
	_, err = f.Seek(offset, 0)
	if err != nil {
		log.Fatalf("unable to seek to %d in %#v: %s", offset, entryFilePath, err)
	}
	if *verbose {
		log.Printf("finished seeking")
	}
	ef := certificatetransparency.EntriesFile{f}

	mapLock := &sync.Mutex{}
	unknowns := make(map[string]int64)
	certCounts := make(map[CAName]int64)
	now := time.Now()
	var ctErrors, certParseErrors int64
	err = ef.Map(func(ep *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			log.Printf("couldn't parse ct entry at byte %d: %s", offset+ep.Offset, err)
			atomic.AddInt64(&ctErrors, 1)
			return
		}

		cert, err := x509.ParseCertificate(ep.Entry.X509Cert)
		if err != nil {
			log.Printf("couldn't parse certificate at byte %d: %s", offset+ep.Offset, err)
			atomic.AddInt64(&certParseErrors, 1)
			return
		}

		if !cert.NotAfter.After(now) {
			return
		}

		issuer := issuerToString(cert.Issuer)
		name := matchCAName(issuer)

		mapLock.Lock()
		defer mapLock.Unlock()

		if name == emptyCAName {
			unknowns[issuer] = ep.Offset
			name = unknownCAName
		}

		c := certCounts[name]
		c++
		certCounts[name] = c
	})

	if err != nil {
		log.Fatalf("error while searching CT entries file: %s", err)
	}
	seen := []string{}
	for k, _ := range certCounts {
		seen = append(seen, string(k))
	}
	sort.Strings(seen)
	for _, n := range seen {
		fmt.Println(n, certCounts[CAName(n)])
	}
	fmt.Printf("num of unknown CAs: %d\n", len(unknowns))
	fmt.Printf("ct entry parse errors: %d, x509 cert parse errors: %d\n", ctErrors, certParseErrors)
}

type CAName string

func issuerToString(issuer pkix.Name) string {
	out := []string{}
	if issuer.CommonName != "" {
		out = append(out, escapedName("CN=", issuer.CommonName))
	}
	out = append(out, escapeMultiple("OU=", issuer.OrganizationalUnit)...)
	out = append(out, escapeMultiple("O=", issuer.Organization)...)
	out = append(out, escapeMultiple("L=", issuer.Locality)...)
	out = append(out, escapeMultiple("ST=", issuer.Province)...)
	out = append(out, escapeMultiple("C=", issuer.Country)...)
	return strings.Join(out, ",")
}

func escapeMultiple(prefix string, values []string) []string {
	out := []string{}
	for _, v := range values {
		if v != "" {
			out = append(out, escapedName(prefix, v))
		}
	}
	return out
}

func escapedName(prefix, value string) string {
	return prefix + strings.Replace(value, ",", "\\,", -1)
}

func matchCAName(name string) CAName {
	n := knownCANames(name)
	if n != emptyCAName {
		return n
	}

	switch {
	case cacertCARegexp.MatchString(name):
		return cacertCAName
	case certumCARegexp.MatchString(name):
		return certumCAName
	case digicertInsensitiveCARegexp.MatchString(name):
		return digicertCAName
	case digicertCARegexp.MatchString(name):
		return digicertCAName
	case entrustCARegexp.MatchString(name):
		return entrustCAName
	case godaddyCARegexp.MatchString(name):
		return godaddyCAName
	case googleCARegexp.MatchString(name):
		return googleCAName
	case globalsignCARegexp.MatchString(name):
		return globalsignCAName
	case letsencryptCARegexp.MatchString(name):
		return letsencryptCAName
	case microsoftCARegexp.MatchString(name):
		return microsoftCAName
	case netsolCARegexp.MatchString(name):
		return netsolCAName
	case quovadisCARegexp.MatchString(name):
		return quovadisCAName
	case secomCARegexp.MatchString(name):
		return secomCAName
	case startcomCARegexp.MatchString(name):
		return startcomCAName
	case symantecCARegexp.MatchString(name):
		return symantecCAName // SYMC_no_auditCAName
	case trendmicroCARegexp.MatchString(name):
		return trendmicroCAName
	case trustwaveCARegexp.MatchString(name):
		return trustwaveCAName
	case wosignCARegexp.MatchString(name):
		return wosignCAName
	case swisssignCARegexp.MatchString(name):
		return swisssignCAName
	case hydrantidCARegexp.MatchString(name):
		return hydrantidCAName
	case buypassCARegexp.MatchString(name):
		return buypassCAName
	case govtKRCARegexp.MatchString(name):
		return govtKRCAName
	case govtUSCARegexp.MatchString(name):
		return govtUSCAName
	case terenaCARegexp.MatchString(name):
		return terenaCAName
	case symantecNoAuditCARegexp.MatchString(name):
		return symantecCAName // SYMC_no_auditCAName
	}

	return emptyCAName
}

var (
	cacertCARegexp              = regexp.MustCompile("(?i)cacert")
	certumCARegexp              = regexp.MustCompile("Certum|Unizet|Dreamcommerce|nazwaSSL")
	digicertInsensitiveCARegexp = regexp.MustCompile("(?i)cybertrust|omniroot")
	digicertCARegexp            = regexp.MustCompile("DigiCert")
	entrustCARegexp             = regexp.MustCompile("Entrust")
	godaddyCARegexp             = regexp.MustCompile("Go Daddy|Starfield")
	googleCARegexp              = regexp.MustCompile("Google Internet Authority")
	globalsignCARegexp          = regexp.MustCompile("GlobalSign|AlphaSSL")
	letsencryptCARegexp         = regexp.MustCompile("Let's Encrypt")
	microsoftCARegexp           = regexp.MustCompile("Microsoft IT SSL SHA")
	netsolCARegexp              = regexp.MustCompile("Network Solutions")
	quovadisCARegexp            = regexp.MustCompile("QuoVadis")
	secomCARegexp               = regexp.MustCompile("SECOM")
	startcomCARegexp            = regexp.MustCompile("StartCom")
	symantecCARegexp            = regexp.MustCompile("GeoTrust|Symantec|VeriSign|thawte|Thawte|Equifax")
	trendmicroCARegexp          = regexp.MustCompile("Trend Micro|AffirmTrust")
	trustwaveCARegexp           = regexp.MustCompile("Trustwave")
	wosignCARegexp              = regexp.MustCompile("WoSign")
	swisssignCARegexp           = regexp.MustCompile("SwissSign")
	hydrantidCARegexp           = regexp.MustCompile("Hydrant")
	buypassCARegexp             = regexp.MustCompile("Buypass")
	govtKRCARegexp              = regexp.MustCompile("O=Government of Korea")
	govtUSCARegexp              = regexp.MustCompile("O=U.S. Government")
	terenaCARegexp              = regexp.MustCompile("TERENA")
	symantecNoAuditCARegexp     = regexp.MustCompile("Volusion|STRATO|,O=Intermediate Certificate,")
)

const (
	emptyCAName   = CAName("")
	unknownCAName = CAName("unknown")

	cacertCAName      = CAName("cacert")
	certumCAName      = CAName("certum")
	comodoCAName      = CAName("comodo")
	digicertCAName    = CAName("digicert")
	entrustCAName     = CAName("entrust")
	godaddyCAName     = CAName("godaddy")
	googleCAName      = CAName("google")
	globalsignCAName  = CAName("globalsign")
	letsencryptCAName = CAName("letsencrypt")
	microsoftCAName   = CAName("microsoft")
	netsolCAName      = CAName("netsol")
	quovadisCAName    = CAName("quovadis")
	secomCAName       = CAName("secom")
	startcomCAName    = CAName("startcom")
	symantecCAName    = CAName("symantec") // SYMC_no_audit
	trendmicroCAName  = CAName("trendmicro")
	trustwaveCAName   = CAName("trustwave")
	wosignCAName      = CAName("wosign")
	swisssignCAName   = CAName("swisssign")
	hydrantidCAName   = CAName("hydrantid")
	buypassCAName     = CAName("buypass")
	govtKRCAName      = CAName("govt_kr")
	govtUSCAName      = CAName("govt_us")
	terenaCAName      = CAName("terena")
)

func knownCANames(name string) CAName {
	if found := symantecNames[name]; found {
		return symantecCAName
	}
	if found := comodoNames[name]; found {
		return comodoCAName
	}
	return emptyCAName
}
