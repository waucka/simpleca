package main

import (
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	_ "github.com/mattn/go-sqlite3"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
)

const (
	caCertKeyUsage   = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	leafCertKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
)

var (
	// DEAR GOD!  WHO THOUGHT THIS WAS A GOOD API?  WHY WHY WHY WHY WHY WHY WHY WHY WHY?
	maxSerial             *big.Int = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(159), nil)
	clientCertExtKeyUsage          = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
	serverCertExtKeyUsage          = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	Day                            = time.Hour * 24
	Year                           = Day * 365
)

type CertDefaults struct {
	DigestAlgo             *string `yaml:"digest_algo"`
	Issuer                 *string `yaml:"issuer"`
	ExpirationDays         *int    `yaml:"expiration_days"`
	CountryName            *string `yaml:"country_name"`
	StateName              *string `yaml:"state_name"`
	LocalityName           *string `yaml:"locality_name"`
	OrganizationName       *string `yaml:"organization_name"`
	OrganizationalUnitName *string `yaml:"organizational_unit_name"`
	EmailAddress           *string `yaml:"email_address"`
}

type Config struct {
	DBFilePath    string        `yaml:"db_file"`
	Defaults      *CertDefaults `yaml:"cert_defaults"`
	DefaultCrypto string        `yaml:"default_crypto"`
}

// Returns a cli.ExitError with the given message, specified in a Printf-like way
func e(format string, a ...interface{}) error {
	msg := fmt.Sprintf(format, a...)
	return cli.NewExitError(msg, 1)
}

func opendb(dbpath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return nil, err
	}

	// TABLE certs
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='certs'")
	if err != nil {
		db.Close()
		return nil, err
	}
	if !rows.Next() {
		_, err := db.Exec("CREATE TABLE certs (id TEXT NOT NULL PRIMARY KEY, revoked INTEGER, parent TEXT, derdata BLOB)")
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	rows.Close()

	// TABLE keys
	rows, err = db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
	if err != nil {
		db.Close()
		return nil, err
	}
	if !rows.Next() {
		_, err := db.Exec("CREATE TABLE keys (id TEXT NOT NULL PRIMARY KEY, keytype TEXT, keydata BLOB)")
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	rows.Close()

	// TABLE csrs
	rows, err = db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='csrs'")
	if err != nil {
		db.Close()
		return nil, err
	}
	if !rows.Next() {
		_, err := db.Exec("CREATE TABLE csrs (id TEXT NOT NULL PRIMARY KEY, csrdata BLOB)")
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	rows.Close()

	return db, nil
}

func loadConfig(configPath string) (*Config, error) {
	var config Config
	configFile, err := os.Open(configPath)
	if os.IsNotExist(err) {
		// No file; use empty strings.
		homeDir, err := homedir.Dir()
		if err != nil {
			return nil, err
		}
		config.DBFilePath = filepath.Join(homeDir, ".simpleca.db")
		config.Defaults = &CertDefaults{}
		config.DefaultCrypto = "rsa:2048"
		return &config, nil
	}
	if err != nil {
		return nil, err
	}
	configData, err := ioutil.ReadAll(configFile)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "simpleca"
	app.Usage = "Manage an x.509 PKI without going mad"
	app.Version = "1.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/simpleca.yaml",
			Usage: "Configuration file",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "createroot",
			Usage:     "Create a root certificate",
			Action:    createRoot,
			ArgsUsage: "IDENTIFIER",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "organization",
					Usage: "Organization of subject",
				},
				cli.StringFlag{
					Name:  "orgunit",
					Usage: "Organizational Unit of subject",
				},
				cli.StringFlag{
					Name:  "name",
					Usage: "Name to use in the generated certificate",
				},
				cli.StringFlag{
					Name:  "crypto",
					Usage: "Cryptographic algorithm for public/private key",
				},
				cli.StringFlag{
					Name:  "digest",
					Usage: "Cryptographic hash for certificate digest",
				},
				cli.IntFlag{
					Name:  "validity",
					Usage: "Number of days from now until certificate expires",
				},
			},
		},
		{
			Name:      "createsub",
			Usage:     "Create a sub-CA certificate",
			Action:    createSub,
			ArgsUsage: "IDENTIFIER",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "issuer",
					Usage: "ID of certificate to sign with",
				},
				cli.StringFlag{
					Name:  "organization",
					Usage: "Organization of subject",
				},
				cli.StringFlag{
					Name:  "orgunit",
					Usage: "Organizational Unit of subject",
				},
				cli.StringFlag{
					Name:  "name",
					Usage: "Name to use in the generated certificate",
				},
				cli.StringFlag{
					Name:  "crypto",
					Usage: "Cryptographic algorithm for public/private key",
				},
				cli.StringFlag{
					Name:  "digest",
					Usage: "Cryptographic hash for certificate digest",
				},
				cli.IntFlag{
					Name:  "validity",
					Usage: "Number of days from now until certificate expires",
				},
			},
		},
		{
			Name:      "issue",
			Usage:     "Issue a server or client certificate",
			Action:    issueCert,
			ArgsUsage: "IDENTIFIER",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "issuer",
					Usage: "ID of certificate to sign with",
				},
				cli.StringFlag{
					Name:  "name",
					Usage: "Name to use in the generated certificate",
				},
				cli.StringFlag{
					Name:  "altnames",
					Usage: "DNS or IP address alternative names to use in the generated certificate",
				},
				cli.StringFlag{
					Name:  "crypto",
					Usage: "Cryptographic algorithm for public/private key",
				},
				cli.StringFlag{
					Name:  "digest",
					Usage: "Cryptographic hash for certificate digest",
				},
				cli.BoolFlag{
					Name:  "server",
					Usage: "Issue a server certificate",
				},
				cli.BoolFlag{
					Name:  "client",
					Usage: "Issue a client certificate",
				},
				cli.IntFlag{
					Name:  "validity",
					Usage: "Number of days from now until certificate expires",
				},
				cli.StringFlag{
					Name:  "country",
					Usage: "Country of subject",
				},
				cli.StringFlag{
					Name:  "state",
					Usage: "State or province of subject",
				},
				cli.StringFlag{
					Name:  "locality",
					Usage: "Locality (e.g. city) of subject",
				},
				cli.StringFlag{
					Name:  "organization",
					Usage: "Organization of subject",
				},
				cli.StringFlag{
					Name:  "orgunit",
					Usage: "Organizational Unit of subject",
				},
				cli.StringFlag{
					Name:  "email",
					Usage: "Contact email address",
				},
			},
		},
		{
			Name:      "renew",
			Usage:     "Renew a previously-issued certificate",
			Action:    renewCert,
			ArgsUsage: "IDENTIFIER",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "validity",
					Usage: "Number of days from now until certificate expires",
				},
			},
		},
		{
			Name:      "revoke",
			Usage:     "Revoke a previously-issued certificate",
			Action:    revokeCert,
			ArgsUsage: "IDENTIFIER",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "out",
					Usage: "Output file",
				},
			},
		},
		{
			Name:      "import",
			Usage:     "Import an object into the database",
			Action:    importObject,
			ArgsUsage: "TYPE/IDENTIFIER",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "in",
					Usage: "Input file",
				},
				cli.StringFlag{
					Name:  "parent",
					Usage: "Parent object ID",
				},
			},
		},
		{
			Name:      "export",
			Usage:     "Export an object from the database",
			Action:    export,
			ArgsUsage: "TYPE/IDENTIFIER",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "out",
					Usage: "Output file",
				},
			},
		},
		{
			Name:      "list",
			Usage:     "List objects in the database",
			Action:    listObjects,
			ArgsUsage: "TYPE",
		},
	}
	app.Run(os.Args)
}

func marshalPrivateKey(privkey interface{}) ([]byte, error) {
	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return b, nil
	default:
		return nil, fmt.Errorf("Invalid private key")
	}
}

func genKeyPair(cryptoAlgo string, cryptoParams string) (pubkey interface{}, privkey interface{}, generr error) {
	var err error
	pubkey = nil
	privkey = nil
	if cryptoAlgo == "rsa" {
		bits, err := strconv.Atoi(cryptoParams)
		if err != nil {
			generr = fmt.Errorf("Invalid RSA key size: %s", cryptoParams)
			return
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			generr = fmt.Errorf("Failed to generate RSA keypair: %s", err.Error())
			return
		}
		pubkey = &priv.PublicKey
		privkey = priv
	} else if cryptoAlgo == "ecdsa" {
		var priv *ecdsa.PrivateKey
		switch cryptoParams {
		case "p224":
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case "p256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "p384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "p521":
			priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			generr = fmt.Errorf("Invalid ECDSA curve: %s", cryptoParams)
			return
		}
		if err != nil {
			generr = fmt.Errorf("Failed to generate ECDSA keypair: %s", err.Error())
			return
		}
		pubkey = &priv.PublicKey
		privkey = priv
	} else {
		generr = fmt.Errorf("Invalid crypto algorithm: %s", cryptoAlgo)
		return
	}
	return
}

func extractCertParamsFromCli(c *cli.Context, config *Config) (certId string, validity int, cryptoAlgo string, cryptoParams string, digestAlgo string, err error) {
	certId = c.Args()[0]

	validity = c.Int("validity")

	cryptoSpec := c.String("crypto")
	if cryptoSpec == "" {
		cryptoSpec = config.DefaultCrypto
	}
	cryptoSpecParts := strings.Split(cryptoSpec, ":")
	if len(cryptoSpecParts) != 2 {
		err = fmt.Errorf("Invalid -crypto %s", cryptoSpec)
		return
	}
	cryptoAlgo = cryptoSpecParts[0]
	cryptoParams = cryptoSpecParts[1]

	digestAlgo = c.String("digest")
	if digestAlgo == "" {
		if config.Defaults.DigestAlgo == nil {
			digestAlgo = "sha256"
		} else {
			digestAlgo = *config.Defaults.DigestAlgo
		}
	}
	return
}

func getx509SigAlgo(cryptoAlgo, digestAlgo string) (x509.SignatureAlgorithm, error) {
	var sigAlgo x509.SignatureAlgorithm
	if digestAlgo == "md5" {
		if cryptoAlgo == "rsa" {
			sigAlgo = x509.MD5WithRSA
		} else {
			return sigAlgo, fmt.Errorf("Invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else if digestAlgo == "sha1" {
		if cryptoAlgo == "rsa" {
			sigAlgo = x509.SHA1WithRSA
		} else if cryptoAlgo == "ecdsa" {
			sigAlgo = x509.ECDSAWithSHA1
		} else {
			return sigAlgo, fmt.Errorf("Invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else if digestAlgo == "sha256" {
		if cryptoAlgo == "rsa" {
			sigAlgo = x509.SHA256WithRSA
		} else if cryptoAlgo == "ecdsa" {
			sigAlgo = x509.ECDSAWithSHA256
		} else {
			return sigAlgo, fmt.Errorf("Invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else if digestAlgo == "sh384" {
		if cryptoAlgo == "rsa" {
			sigAlgo = x509.SHA384WithRSA
		} else if cryptoAlgo == "ecdsa" {
			sigAlgo = x509.ECDSAWithSHA384
		} else {
			return sigAlgo, fmt.Errorf("Invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else if digestAlgo == "sha512" {
		if cryptoAlgo == "rsa" {
			sigAlgo = x509.SHA512WithRSA
		} else if cryptoAlgo == "ecdsa" {
			sigAlgo = x509.ECDSAWithSHA512
		} else {
			return sigAlgo, fmt.Errorf("Invalid crypto/digest combination: %s/%s", cryptoAlgo, digestAlgo)
		}
	} else {
		return sigAlgo, fmt.Errorf("Invalid digest algorithm: %s", digestAlgo)
	}
	return sigAlgo, nil
}

func makeNameSlice(c *cli.Context, key string, defaultValue *string) []string {
	val := c.String(key)
	if val != "" {
		return []string{val}
	} else if val == "nil" {
		return nil
	} else if defaultValue != nil {
		return []string{*defaultValue}
	} else {
		return nil
	}
}

func buildNameFromCli(c *cli.Context, config *Config) pkix.Name {
	return pkix.Name{
		CommonName:         c.String("name"),
		Country:            makeNameSlice(c, "country", config.Defaults.CountryName),
		Organization:       makeNameSlice(c, "organization", config.Defaults.OrganizationName),
		OrganizationalUnit: makeNameSlice(c, "orgunit", config.Defaults.OrganizationalUnitName),
		Locality:           makeNameSlice(c, "locality", config.Defaults.LocalityName),
		Province:           makeNameSlice(c, "state", config.Defaults.StateName),
	}
}

func storeCertAndKey(db *sql.DB, certId, parentId string, derBytes []byte, cryptoAlgo string, keydata []byte) error {
	var err error
	if parentId == "" {
		_, err = db.Exec("INSERT INTO certs (id, revoked, parent, derdata) VALUES (?, 0, NULL, ?)", certId, derBytes)
	} else {
		_, err = db.Exec("INSERT INTO certs (id, revoked, parent, derdata) VALUES (?, 0, ?, ?)", certId, parentId, derBytes)
	}
	if err != nil {
		return fmt.Errorf("Failed to store certificate in database: %s", err.Error())
	}

	_, err = db.Exec("INSERT INTO keys (id, keytype, keydata) VALUES (?, ?, ?)", certId, cryptoAlgo, keydata)
	if err != nil {
		return fmt.Errorf("Failed to store private key in database: %s", err.Error())
	}

	return nil
}

func updateCert(db *sql.DB, certId string, derBytes []byte) error {
	_, err := db.Exec("UPDATE certs SET derdata = ? WHERE id = ?", derBytes, certId)
	if err != nil {
		return fmt.Errorf("Failed to update certificate in database: %s", err.Error())
	}

	return nil
}

func storeCSR(db *sql.DB, certId string, derBytes []byte) error {
	_, err := db.Exec("INSERT INTO csrs (id, csrdata) VALUES (?, ?)", certId, derBytes)
	if err != nil {
		return fmt.Errorf("Failed to store CSR in database: %s", err.Error())
	}

	return nil
}

func stupidCsrDance(template *x509.CertificateRequest, privkey interface{}, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, isCA bool) ([]byte, *x509.Certificate, error) {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privkey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create leaf CSR: %s", err.Error())
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to reload leaf CSR (this should never happen!): %s", err.Error())
	}
	certTemplate, err := certFromCsr(csr, keyUsage, extKeyUsage, isCA)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate template from CSR: %s", err.Error())
	}
	return csrBytes, certTemplate, nil
}

func generateCACert(c *cli.Context, config *Config, db *sql.DB, parentId string, parentCert *x509.Certificate, signkey interface{}) error {
	if !(signkey == nil && parentCert == nil && parentId == "") && !(signkey != nil && parentCert != nil && parentId != "") {
		return e("Internal programming error.  Please slap developer.")
	}

	certId, validity, cryptoAlgo, cryptoParams, digestAlgo, err := extractCertParamsFromCli(c, config)
	if err != nil {
		return e(err.Error())
	}
	if validity == 0 {
		return e("Must specify -validity for root and intermediate certificates")
	}
	sigAlgo, err := getx509SigAlgo(cryptoAlgo, digestAlgo)
	if err != nil {
		return e(err.Error())
	}

	pubkey, privkey, err := genKeyPair(cryptoAlgo, cryptoParams)
	if err != nil {
		return e(err.Error())
	}

	fullName := buildNameFromCli(c, config)
	if fullName.CommonName == "" {
		return e("Must specify at least -name")
	}

	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return e("Failed to generate random serial number (WTF is wrong with your machine?)")
	}
	keydata, err := marshalPrivateKey(privkey)
	if err != nil {
		return e("Failed to marshal private key")
	}
	now := time.Now()
	var derBytes []byte
	if signkey == nil && parentCert == nil && parentId == "" {
		template := x509.Certificate{
			SignatureAlgorithm:    sigAlgo,
			PublicKey:             pubkey,
			SerialNumber:          serial,
			Subject:               fullName,
			NotBefore:             now.Add(-10 * time.Minute).UTC(),
			NotAfter:              now.Add(time.Duration(validity*24) * time.Hour).UTC(),
			KeyUsage:              caCertKeyUsage,
			BasicConstraintsValid: true,
			IsCA:       true,
			MaxPathLen: -1,
		}
		signkey = privkey
		parentCert = &template
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, parentCert, pubkey, signkey)
		if err != nil {
			return e("Failed to create CA certificate: %s", err.Error())
		}
	} else {
		templateCSR := x509.CertificateRequest{
			SignatureAlgorithm: sigAlgo,
			PublicKey:          pubkey,
			Subject:            fullName,
		}
		csrBytes, template, err := stupidCsrDance(&templateCSR, privkey, caCertKeyUsage, nil, true)
		if err != nil {
			return e(err.Error())
		}
		template.NotBefore = now.Add(-10 * time.Minute).UTC()
		template.NotAfter = now.Add(time.Duration(validity*24) * time.Hour).UTC()
		derBytes, err = x509.CreateCertificate(rand.Reader, template, parentCert, pubkey, signkey)
		if err != nil {
			return e("Failed to create CA certificate: %s", err.Error())
		}
		// We wait until here to store the CSR because non-DB things can fail before this point.
		err = storeCSR(db, certId, csrBytes)
		if err != nil {
			return e(err.Error())
		}
	}

	err = storeCertAndKey(db, certId, parentId, derBytes, cryptoAlgo, keydata)
	if err != nil {
		return e(err.Error())
	}

	return nil
}

func certFromCsr(csr *x509.CertificateRequest, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, isCA bool) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate random serial number (WTF is wrong with your machine?)")
	}
	maxPathLen := 0
	if isCA {
		// HARDCODING!  BAH!
		maxPathLen = -1
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now.Add(-10 * time.Minute).UTC(),
		NotAfter:              now.Add(3 * Year).UTC(),
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		BasicConstraintsValid: true,
		IsCA:           isCA,
		MaxPathLen:     maxPathLen,
		MaxPathLenZero: maxPathLen == 0,
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
	}, nil
}

func generateLeafCert(c *cli.Context, config *Config, db *sql.DB, parentId string, parentCert *x509.Certificate, signkey interface{}) error {
	if signkey == nil || parentCert == nil || parentId == "" {
		return e("Internal programming error.  Please slap developer.")
	}

	if c.Bool("server") && c.Bool("client") {
		return e("A certificate can be for a client or a server.  Pick one.")
	}
	if !c.Bool("server") && !c.Bool("client") {
		return e("A certificate must be for a client or a server.  Pick one.")
	}

	certId, validity, cryptoAlgo, cryptoParams, digestAlgo, err := extractCertParamsFromCli(c, config)
	if err != nil {
		return e(err.Error())
	}
	if validity == 0 {
		if config.Defaults.ExpirationDays != nil {
			validity = *config.Defaults.ExpirationDays
		} else {
			validity = 365
		}
	}

	sigAlgo, err := getx509SigAlgo(cryptoAlgo, digestAlgo)
	if err != nil {
		return e(err.Error())
	}

	pubkey, privkey, err := genKeyPair(cryptoAlgo, cryptoParams)
	if err != nil {
		return e(err.Error())
	}

	fullName := buildNameFromCli(c, config)
	if fullName.CommonName == "" {
		return e("Must specify at least -name")
	}

	var extKeyUsage []x509.ExtKeyUsage
	if c.Bool("server") {
		extKeyUsage = serverCertExtKeyUsage
	} else if c.Bool("client") {
		extKeyUsage = clientCertExtKeyUsage
	}
	now := time.Now()
	templateCSR := x509.CertificateRequest{
		SignatureAlgorithm: sigAlgo,
		PublicKey:          pubkey,
		Subject:            fullName,
	}

	altnames := strings.Split(c.String("altnames"), ",")
	for _, altname := range altnames {
		if ip := net.ParseIP(altname); ip != nil {
			templateCSR.IPAddresses = append(templateCSR.IPAddresses, ip)
		} else {
			templateCSR.DNSNames = append(templateCSR.DNSNames, altname)
			fmt.Printf("added DNS altname: %s\n", altname)
		}
	}

	csrBytes, template, err := stupidCsrDance(&templateCSR, privkey, leafCertKeyUsage, extKeyUsage, false)
	template.NotBefore = now.Add(-10 * time.Minute).UTC()
	template.NotAfter = now.Add(time.Duration(validity*24) * time.Hour).UTC()
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubkey, signkey)
	if err != nil {
		return e("Failed to create CA certificate: %s", err.Error())
	}
	// We wait until here to store the CSR because non-DB things can fail before this point.
	err = storeCSR(db, certId, csrBytes)
	if err != nil {
		return e(err.Error())
	}

	keydata, err := marshalPrivateKey(privkey)
	if err != nil {
		return e("Failed to marshal private key")
	}

	err = storeCertAndKey(db, certId, parentId, derBytes, cryptoAlgo, keydata)
	if err != nil {
		return e(err.Error())
	}

	return nil
}

func createRoot(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}

	err = generateCACert(c, config, db, "", nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func getRootCertId(db *sql.DB, certId string) (string, error) {
	rootId := certId
	for rootId != "" {
		rows, err := db.Query("SELECT parent FROM certs WHERE id = ?", rootId)
		if err != nil {
			return "", fmt.Errorf("Failed to query DB for cert/%s", rootId)
		}
		defer rows.Close()
		if rows.Next() {
			var parentId *string
			err := rows.Scan(&parentId)
			if err != nil {
				return "", fmt.Errorf("Failed to get parent ID for cert/%s", certId)
			}
			if parentId == nil {
				return rootId, nil
			}
			rootId = *parentId
		} else {
			return "", fmt.Errorf("cert/%s does not exist.", certId)
		}
	}
	return "", fmt.Errorf("Failed to find root certificate for cert/%s", certId)
}

func certFromDB(db *sql.DB, certId string) (*x509.Certificate, error) {
	rows, err := db.Query("SELECT derdata FROM certs WHERE id = ? AND revoked = 0", certId)
	if err != nil {
		return nil, fmt.Errorf("Failed to query DB for cert/%s", certId)
	}
	defer rows.Close()
	if rows.Next() {
		var derdata []byte
		err := rows.Scan(&derdata)
		if err != nil {
			return nil, fmt.Errorf("Failed to extract DER data for cert/%s", certId)
		}
		return x509.ParseCertificate(derdata)
	} else {
		return nil, fmt.Errorf("cert/%s does not exist or has been revoked.", certId)
	}
}

func getParent(db *sql.DB, certId string) (*x509.Certificate, interface{}, error) {
	rows, err := db.Query("SELECT certs.derdata, keys.keytype, keys.keydata FROM certs, keys WHERE certs.id = (SELECT parent FROM certs WHERE id = ?) AND certs.id = keys.id", certId)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to query DB for cert/%s", certId)
	}
	defer rows.Close()
	if rows.Next() {
		var derdata []byte
		var keytype string
		var keydata []byte
		err := rows.Scan(&derdata, &keytype, &keydata)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to extract parent cert/key data for id %s", certId)
		}
		cert, err := x509.ParseCertificate(derdata)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to parse parent cert data for id %s", certId)
		}
		var key interface{}
		switch keytype {
		case "rsa":
			key, err = x509.ParsePKCS1PrivateKey(keydata)
		case "ecdsa":
			key, err = x509.ParseECPrivateKey(keydata)
		default:
			return nil, nil, fmt.Errorf("Unknown key type %s for parent key", keytype)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to parse parent key data for id %s", certId)
		}
		return cert, key, nil
	} else {
		return nil, nil, fmt.Errorf("cert/%s does not exist.", certId)
	}
}

func csrFromDB(db *sql.DB, certId string) (*x509.CertificateRequest, error) {
	rows, err := db.Query("SELECT csrdata FROM csrs WHERE id = ?", certId)
	if err != nil {
		return nil, fmt.Errorf("Failed to query DB for csr/%s", certId)
	}
	defer rows.Close()
	if rows.Next() {
		var csrdata []byte
		err := rows.Scan(&csrdata)
		if err != nil {
			return nil, fmt.Errorf("Failed to extract DER data for csr/%s", certId)
		}
		return x509.ParseCertificateRequest(csrdata)
	} else {
		return nil, fmt.Errorf("csr/%s does not exist.", certId)
	}
}

func keyFromDB(db *sql.DB, keyId string) (interface{}, error) {
	rows, err := db.Query("SELECT keytype, keydata FROM keys WHERE id = ?", keyId)
	if err != nil {
		return nil, fmt.Errorf("Failed to query DB for key/%s", keyId)
	}
	defer rows.Close()
	if rows.Next() {
		var keytype string
		var keydata []byte
		err := rows.Scan(&keytype, &keydata)
		if err != nil {
			return nil, fmt.Errorf("Failed to extract key data for key/%s", keyId)
		}
		switch keytype {
		case "rsa":
			return x509.ParsePKCS1PrivateKey(keydata)
		case "ecdsa":
			return x509.ParseECPrivateKey(keydata)
		default:
			return nil, fmt.Errorf("Unknown key type %s for key/%s", keytype, keyId)
		}
	} else {
		return nil, fmt.Errorf("key/%s does not exist.", keyId)
	}
}

func createSub(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}

	issuerId := c.String("issuer")
	if issuerId == "" {
		return e("Must specify issuer")
	}

	cert, err := certFromDB(db, issuerId)
	if err != nil {
		return e("Failed to retrieve signing certificate: %s", err.Error())
	}
	signkey, err := keyFromDB(db, issuerId)
	if err != nil {
		return e("Failed to retrieve signing key: %s", err.Error())
	}

	err = generateCACert(c, config, db, issuerId, cert, signkey)
	if err != nil {
		return err
	}

	return nil
}

func issueCert(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}

	issuerId := c.String("issuer")
	if issuerId == "" {
		return e("Must specify issuer")
	}

	cert, err := certFromDB(db, issuerId)
	if err != nil {
		return e("Failed to retrieve signing certificate: %s", err.Error())
	}
	signkey, err := keyFromDB(db, issuerId)
	if err != nil {
		return e("Failed to retrieve signing key: %s", err.Error())
	}

	err = generateLeafCert(c, config, db, issuerId, cert, signkey)
	if err != nil {
		return err
	}

	return nil
}

func renewCert(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}

	certId := c.Args()[0]
	issuerId := c.String("issuer")
	validity := c.Int("validity")
	if validity == 0 {
		if config.Defaults.ExpirationDays != nil {
			validity = *config.Defaults.ExpirationDays
		} else {
			validity = 365
		}
	}

	var parentCert *x509.Certificate
	var signkey interface{}
	if issuerId == "" {
		parentCert, signkey, err = getParent(db, certId)
		if err != nil {
			return e("Failed to retrieve issuer for certificate %s: %s", certId, err.Error())
		}
	} else {
		parentCert, err = certFromDB(db, issuerId)
		if err != nil {
			return e("Failed to retrieve signing certificate: %s", err.Error())
		}

		signkey, err = keyFromDB(db, issuerId)
		if err != nil {
			return e("Failed to retrieve signing key: %s", err.Error())
		}
	}

	oldCert, err := certFromDB(db, certId)
	if err != nil {
		return e("Failed to retrieve old certificate: %s", err.Error())
	}

	csr, err := csrFromDB(db, certId)
	if err != nil {
		return e("Failed to retrieve stored CSR: %s", err.Error())
	}

	var extKeyUsage []x509.ExtKeyUsage
	if c.Bool("server") {
		extKeyUsage = serverCertExtKeyUsage
	} else if c.Bool("client") {
		extKeyUsage = clientCertExtKeyUsage
	}
	now := time.Now()
	template, err := certFromCsr(csr, leafCertKeyUsage, extKeyUsage, oldCert.IsCA)
	if err != nil {
		return e("Failed to create certificate template from CSR: %s", err.Error())
	}

	template.NotBefore = now.Add(-10 * time.Minute).UTC()
	template.NotAfter = now.Add(time.Duration(validity*24) * time.Hour).UTC()
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, oldCert.PublicKey, signkey)
	if err != nil {
		return e("Failed to create certificate: %s", err.Error())
	}

	err = updateCert(db, certId, derBytes)
	if err != nil {
		return e(err.Error())
	}

	return nil
}

func revokeCert(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}

	certId := c.Args()[0]
	cert, err := certFromDB(db, certId)
	if err != nil {
		return e("Failed to retrieve certificate: %s", err.Error())
	}
	rootIssuerId, err := getRootCertId(db, certId)
	if err != nil {
		return e("Failed to find root certificate: %s", err.Error())
	}
	signkey, err := keyFromDB(db, rootIssuerId)
	if err != nil {
		return e("Failed to retrieve signing key: %s", err.Error())
	}

	now := time.Now()
	revokedCerts := []pkix.RevokedCertificate{
		pkix.RevokedCertificate{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: now,
			Extensions:     nil,
		},
	}
	expiration := now.Add(Day).UTC()
	crlBytes, err := cert.CreateCRL(rand.Reader, signkey, revokedCerts, now, expiration)

	_, err = db.Exec("UPDATE certs SET revoked = ? WHERE id = ?", 1, certId)
	if err != nil {
		return e("Failed to update certificate in database: %s", err.Error())
	}

	outpath := c.String("out")
	var out io.Writer
	if outpath == "" || outpath == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(outpath)
		if err != nil {
			return e("Failed to create output file: %s", err.Error())
		}
		out = f
		defer f.Close()
	}

	_, err = out.Write(crlBytes)
	if err != nil {
		return e("Failed to write CRL: %s", err.Error())
	}

	return nil
}

func importObject(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}
	objectSpec := c.Args()[0]
	specParts := strings.Split(objectSpec, "/")
	if len(specParts) != 2 {
		return e("Object spec must be of the form type/identifier")
	}

	inpath := c.String("in")
	var in io.Reader
	if inpath == "" || inpath == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(inpath)
		if err != nil {
			return e("Failed to open input file: %s", err.Error())
		}
		in = f
		defer f.Close()
	}

	switch specParts[0] {
	case "cert":
		parentId := c.String("parent")
		pemBytes, err := ioutil.ReadAll(in)
		if err != nil {
			return e(err.Error())
		}
		derBlock, rest := pem.Decode(pemBytes)
		if err != nil {
			return e("Expected PEM-format certificate: %s", err.Error())
		}
		if rest != nil && len(rest) > 0 {
			io.WriteString(os.Stderr, "Multiple certificates provided; only the first one will be imported.\n")
		}
		if derBlock.Type != "CERTIFICATE" {
			return e("Expected PEM-format certificate, got %s instead", derBlock.Type)
		}
		if parentId == "" {
			_, err = db.Exec("INSERT INTO certs (id, revoked, parent, derdata) VALUES (?, 0, NULL, ?)", specParts[1], derBlock.Bytes)
		} else {
			_, err = db.Exec("INSERT INTO certs (id, revoked, parent, derdata) VALUES (?, 0, ?, ?)", specParts[1], parentId, derBlock.Bytes)
		}
		if err != nil {
			return fmt.Errorf("Failed to store certificate in database: %s", err.Error())
		}
	case "key":
		parentId := c.String("parent")
		if parentId != "" {
			return e("-parent is only valid for certificates")
		}
		pemBytes, err := ioutil.ReadAll(in)
		if err != nil {
			return e(err.Error())
		}
		keyBlock, rest := pem.Decode(pemBytes)
		if err != nil {
			return e("Expected PEM-format key: %s", err.Error())
		}
		if rest != nil && len(rest) > 0 {
			io.WriteString(os.Stderr, "Multiple keys provided; only the first one will be imported.\n")
		}
		var keytype string
		if keyBlock.Type == "RSA PRIVATE KEY" {
			keytype = "rsa"
		} else if keyBlock.Type != "EC PRIVATE KEY" {
			keytype = "ecdsa"
		} else {
			return e("Expected PEM-format RSA or EC key, got %s instead", keyBlock.Type)
		}

		_, err = db.Exec("INSERT INTO keys (id, keytype, keydata) VALUES (?, ?, ?)", specParts[1], keytype, keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to store key in database: %s", err.Error())
		}
	case "csr":
		parentId := c.String("parent")
		if parentId != "" {
			return e("-parent is only valid for certificates")
		}
		pemBytes, err := ioutil.ReadAll(in)
		if err != nil {
			return e(err.Error())
		}
		derBlock, rest := pem.Decode(pemBytes)
		if err != nil {
			return e("Expected PEM-format CSR: %s", err.Error())
		}
		if rest != nil && len(rest) > 0 {
			io.WriteString(os.Stderr, "Multiple CSRs provided; only the first one will be imported.\n")
		}
		if derBlock.Type != "CERTIFICATE REQUEST" {
			return e("Expected PEM-format CSR, got %s instead", derBlock.Type)
		}
		err = storeCSR(db, specParts[1], derBlock.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to store CSR in database: %s", err.Error())
		}
	default:
		return e("Unknown object type %s", specParts[0])
	}
	return nil
}

func export(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}
	objectSpec := c.Args()[0]
	specParts := strings.Split(objectSpec, "/")
	if len(specParts) != 2 {
		return e("Object spec must be of the form type/identifier")
	}

	outpath := c.String("out")
	var out io.Writer
	if outpath == "" || outpath == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(outpath)
		if err != nil {
			return e("Failed to create output file: %s", err.Error())
		}
		out = f
		defer f.Close()
	}

	switch specParts[0] {
	case "cert":
		certId := specParts[1]
		rows, err := db.Query("SELECT derdata FROM certs WHERE id = ?", certId)
		if err != nil {
			return e("Failed to query DB for cert/%s", certId)
		}
		defer rows.Close()
		if rows.Next() {
			var derdata []byte
			err := rows.Scan(&derdata)
			if err != nil {
				return e("Failed to extract DER data for cert/%s", certId)
			}
			pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derdata})
		} else {
			return e("cert/%s does not exist.", certId)
		}
	case "key":
		keyId := specParts[1]
		rows, err := db.Query("SELECT keytype, keydata FROM keys WHERE id = ?", keyId)
		if err != nil {
			return e("Failed to query DB for key/%s", keyId)
		}
		defer rows.Close()
		if rows.Next() {
			var keytype string
			var keydata []byte
			err := rows.Scan(&keytype, &keydata)
			if err != nil {
				return e("Failed to extract key data for key/%s", keyId)
			}
			switch keytype {
			case "rsa":
				pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keydata})
			case "ecdsa":
				pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keydata})
			default:
				return e("Unknown key type %s for key/%s", keytype, keyId)
			}
		} else {
			return e("key/%s does not exist.", keyId)
		}
	case "csr":
		certId := specParts[1]
		rows, err := db.Query("SELECT csrdata FROM csrs WHERE id = ?", certId)
		if err != nil {
			return e("Failed to query DB for csr/%s", certId)
		}
		defer rows.Close()
		if rows.Next() {
			var derdata []byte
			err := rows.Scan(&derdata)
			if err != nil {
				return e("Failed to extract DER data for csr/%s", certId)
			}
			pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derdata})
		} else {
			return e("csr/%s does not exist.", certId)
		}
	default:
		return e("Unknown object type %s", specParts[0])
	}
	return nil
}

func listObjects(c *cli.Context) error {
	configPath := c.Parent().String("config")
	config, err := loadConfig(configPath)
	if err != nil {
		return e("Failed to load config file %s: %s", configPath, err.Error())
	}
	db, err := opendb(config.DBFilePath)
	if err != nil {
		return e("Failed to open sqlite3 DB at %s: %s", config.DBFilePath, err.Error())
	}
	defer db.Close()

	if len(c.Args()) != 1 {
		cli.ShowAppHelpAndExit(c, 1)
	}
	objectType := c.Args()[0]

	switch objectType {
	case "certs":
		rows, err := db.Query("SELECT id, parent FROM certs")
		if err != nil {
			return e("Failed to query DB for certificates")
		}
		defer rows.Close()
		for rows.Next() {
			var certId string
			var parentId *string
			err := rows.Scan(&certId, &parentId)
			if err != nil {
				return e("This should not be possible! %s", err.Error())
			}
			if parentId != nil {
				fmt.Printf("%s (parent: %s)\n", certId, *parentId)
			} else {
				fmt.Printf("%s\n", certId)
			}
		}
	case "keys":
		rows, err := db.Query("SELECT id FROM keys")
		if err != nil {
			return e("Failed to query DB for keys")
		}
		defer rows.Close()
		for rows.Next() {
			var keyId string
			err := rows.Scan(&keyId)
			if err != nil {
				return e("This should not be possible! %s", err.Error())
			}
			fmt.Println(keyId)
		}
	case "csrs":
		rows, err := db.Query("SELECT id FROM csrs")
		if err != nil {
			return e("Failed to query DB for csrs")
		}
		defer rows.Close()
		for rows.Next() {
			var csrId string
			err := rows.Scan(&csrId)
			if err != nil {
				return e("This should not be possible! %s", err.Error())
			}
			fmt.Println(csrId)
		}
	default:
		return e("Unknown object type %s", objectType)
	}
	return nil
}
