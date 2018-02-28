// android_pkgs.go -- Parsing Android Packages list
//
// (c) 2016 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

// Android package lives in android/pkg
package pkg // android/pkg

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

// Exported, XML package
type PackageDB struct {

	// Path to packages.list and packages.xml
	list string
	xml  string

	// time of last update
	lastUpd time.Time

	// lookup by package name
	byName map[string]*Pkg

	// lookup packages mapping to a UID
	byUid map[uint32][]*Pkg
}

// Common struct for packages.xml and packages.list
// Some fields are unique to one but not the other
type Pkg struct {
	Name     string
	DataPath string // only in .list
	Path     string
	Uid      uint32

	// The next two fields are for packages.list
	SEinfo string
	Gid    []uint32

	// If one exists - also only in .xml
	Cert *x509.Certificate

	// SHA1 hash of the DER encoding of certificate
	Certhash []byte
}

func (p *Pkg) String() string {
	crt := ""

	if p.Cert != nil {
		crt = fmt.Sprintf(" [SN/%s: hash/%x]", p.Cert.Subject.CommonName, p.Certhash)
	}
	return fmt.Sprintf("%s: %v%s", p.Name, p.Uid, crt)
}

// Open the Android Package DB represented by two files
// 'packages.xml' and 'packages.list' -- respectively 'xml', 'list'
// input args
func OpenPackageDB(xml, list string) (*PackageDB, error) {
	db := &PackageDB{list: list, xml: xml}

	err := db.refresh()
	return db, err
}

// XXX What to implement here?
func (db *PackageDB) Close() {
	db.byName = nil
	db.byUid = nil
}

// Given an UID, return the list of packages that use it
func (db *PackageDB) GetListByUid(uid uint32) []*Pkg {
	db.maybeRefresh()

	if r, ok := db.byUid[uid]; ok {
		return r
	}

	return nil
}

func (db *PackageDB) GetByName(nm string) *Pkg {
	db.maybeRefresh()

	if r, ok := db.byName[nm]; ok {
		return r
	}
	return nil
}

func (db *PackageDB) LastUpdate() time.Time {
	return db.lastUpd
}

// Given a Package UID, return the first matching uid
func (db *PackageDB) GetByUid(uid uint32) *Pkg {
	db.maybeRefresh()

	if r, ok := db.byUid[uid]; ok {
		return r[0]
	}
	return nil
}

// Start an iterator - based on Name
// Creates and returns a channel and feeds it data via a go routine
func (db *PackageDB) IterateByName() chan *Pkg {
	ch := make(chan *Pkg, 1)

	go func(db *PackageDB, ch chan *Pkg) {
		for _, p := range db.byName {
			ch <- p
		}
		close(ch)
	}(db, ch)

	return ch
}

// Start an iterator - based on Uid
// Creates and returns a channel and feeds it data via a go routine
func (db *PackageDB) IterateByUid() chan []*Pkg {
	ch := make(chan []*Pkg, 1)

	go func(db *PackageDB, ch chan []*Pkg) {
		for _, p := range db.byUid {
			ch <- p
		}
		close(ch)
	}(db, ch)

	return ch
}

// If the packages.{list,xml} is newer than what we have, update our
// in-core data.
func (db *PackageDB) maybeRefresh() {
	st0, err := os.Stat(db.list)
	if err != nil {
		return
	}

	st1, err := os.Stat(db.xml)
	if err != nil {
		return
	}

	mt0 := st0.ModTime()
	mt1 := st1.ModTime()
	if mt0.After(db.lastUpd) || mt1.After(db.lastUpd) {
		db.refresh()
	}
}

// Read and update the package DB
func (db *PackageDB) refresh() error {
	ll, err := parseList(db.list)
	if err != nil {
		return err
	}

	xx, err := parseXML(db.xml)
	if err != nil {
		return err
	}

	// We always make new maps and discard the previous ones.
	// This is the only clean way to guarantee that when apps are
	// deleted, our data is valid.
	byName := make(map[string]*Pkg)
	byUid := make(map[uint32][]*Pkg)

	// Start with canonical representation from packages.xml
	for _, p := range xx {
		byName[p.Name] = p
	}

	// And merge data from packages.list into it
	for _, p := range ll {
		if a, ok := byName[p.Name]; ok {
			a.Gid = p.Gid
			a.DataPath = p.DataPath
		} else {
			byName[p.Name] = p
		}
	}

	// Finally, add a reverse lookup
	for _, p := range byName {
		byUid[p.Uid] = append(byUid[p.Uid], p)
	}

	// Finally, if we are NOT on Android, add the calling process to
	// the DB for debugging purposes
	if p := getself(); p != nil {
		byUid[p.Uid] = append(byUid[p.Uid], p)
		byName[p.Name] = p
	}

	db.byName = byName
	db.byUid = byUid
	db.lastUpd = time.Now().UTC()

	return nil
}

// Generator to yield lines into a channel
func genlines(ifd io.Reader) chan []byte {
	rr := bufio.NewReader(ifd)
	ch := make(chan []byte, 10)

	fn := func(r *bufio.Reader, ch chan []byte) {
		for {
			b, err := r.ReadBytes('\n')
			x := len(b)
			if x == 0 {
				if err == io.EOF {
					break
				}
				continue
			}

			if b[x-1] == '\n' {
				b = b[:x-1]
				x -= 1
			}

			if x == 0 {
				continue
			}

			if b[x-1] == '\r' {
				b = b[:x-1]
				x -= 1
			}

			if x == 0 {
				continue
			}

			ch <- b
		}
		close(ch)
	}

	go fn(rr, ch)

	return ch
}

// Parse packages.list
// packages.list format:
//  pkgName   uid  debug(0|1)   dataPath  seInfo  gid[,gid]..
func parseList(fn string) ([]*Pkg, error) {
	//if !exists(fn) { return nil, nil }

	ifd, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	defer ifd.Close()

	// Async scan of the file and generate full lines
	ch := genlines(ifd)

	// Conservatively
	var pa []*Pkg

	for l := range ch {
		v := bytes.Fields(l)
		if len(v) == 0 {
			continue
		}

		// 0 pkgName    (string)
		// 1 Uid        (uint32)
		// 2 Debug      (0|1)
		// 3 dataPath   (string)
		// 4 seInfo     (string)
		// 5 gid_str    (string) -- comma separated or "none"

		u, err := strconv.ParseUint(string(v[1]), 0, 32)
		if err != nil {
			return nil, fmt.Errorf("Cannot parse UID <%s> for %s: %s", string(v[1]), string(v[0]), err)
		}

		var gid []uint32
		if string(v[5]) != "none" {
			z := bytes.Split(v[5], []byte(","))
			for _, gs := range z {
				g, err := strconv.ParseUint(string(gs), 0, 32)
				if err != nil {
					return nil, fmt.Errorf("Cannot parse GID <%s> for %s: %s", string(gs), string(v[0]), err)
				}
				gid = append(gid, uint32(g))
			}
		}

		p := &Pkg{}
		p.Name = string(v[0])
		p.Uid = uint32(u)
		p.DataPath = string(v[3])
		p.SEinfo = string(v[4])
		p.Gid = gid

		pa = append(pa, p)

		//fmt.Printf("<%d>: %s ..\n", p.Uid, p.Name)
	}

	return pa, nil
}

// Return True if file exists and readable; False otherwise
// XXX See how fukked-up the go APIs are? Why did they choose to
//     ignore so many good role models (eg., Python os.path)?
func exists(fn string) bool {
	st, err := os.Stat(fn)
	if os.IsNotExist(err) {
		return false
	}
	if !st.Mode().IsRegular() {
		return false
	}

	return true
}

// XML Package top level struct
type xPackage struct {
	XMLName xml.Name      `xml:"packages"`
	Ver     []xPackageVer `xml:"version"`

	Pkgs []xpkg `xml:"package"`
}

// Header info
type xPackageVer struct {
	SdkVer  string `xml:"sdkVersion,attr"`
	DBVer   string `xml:"databaseVersion,attr"`
	FP      string `xml:"fingerprint,attr"`
	VolUUID string `xml:"volumeUuid,attr"`
}

// Array of these structures
type xpkg struct {
	Name       string `xml:"name,attr"`
	Path       string `xml:"codePath,attr"`
	NativePath string `xml:"nativeLibraryPath,attr"`
	PubFlags   uint32 `xml:"publicFlags,attr"`
	Uid        uint32 `xml:"userId,attr"`
	SharedUid  uint32 `xml:"sharedUserId,attr"`
	Inst       string `xml:"installer,attr"`
	Version    string `xml:"version,attr"`

	// Parsed cert or null
	//Cert    *x509.Certificate

	// The cert is DER encoded and then hexified.
	// So, to get the actual cert, we do unhex -> UnDER
	//Cert    string      `xml:"key,attr">sigs>cert`
	Certstr cert `xml:"sigs>cert"`
}

type cert struct {
	Cert string `xml:"key,attr"`
}

// Parse packages.xml
func parseXML(fn string) ([]*Pkg, error) {

	//if !exists(fn) { return nil, nil }

	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	var v xPackage

	err = xml.Unmarshal(data, &v)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse %s: %s", fn, err)
	}

	g := make([]*Pkg, len(v.Pkgs))

	for i, x := range v.Pkgs {
		y := &Pkg{}
		g[i] = y

		y.Name = x.Name
		y.Path = x.Path
		if x.Uid > 0 {
			y.Uid = x.Uid
		} else if x.SharedUid > 0 {
			y.Uid = x.SharedUid
		} else {
			return nil, fmt.Errorf("%s: uid and sharedUid are both Nil!\n", x.Name)
		}

		// Now try to decode the cert
		if len(x.Certstr.Cert) > 0 {
			b, err := hex.DecodeString(x.Certstr.Cert)
			if err != nil {
				return nil, fmt.Errorf("%s: Can't decode cert hex: %s", x.Name, err)
			}

			if len(b) > 0 {
				crt, err := x509.ParseCertificate(b[:])
				if err != nil {
					return nil, fmt.Errorf("%s: Can't parse X509 DER cert: %s", x.Name, err)
				}

				ch := sha1.Sum(b)
				y.Cert = crt
				y.Certhash = ch[:]
			}
		}

		//fmt.Printf("<%d>:  %s .. [x]\n", x.Uid, x.Name)
	}

	return g, nil
}
