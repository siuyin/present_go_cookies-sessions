package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"golang.org/x/crypto/bcrypt"
)

//sS OMIT

// Session tracks a user session.
type Session struct {
	ID      string // session ID
	UserID  string // ID of authorized user for which this session is maintained
	Expires time.Time
	dur     time.Duration // duration for which session is valid
}

//sE OMIT

// 10 OMIT

// SessStore is a session store.
type SessStore struct {
	GCInterval time.Duration
	m          map[string]Session
	l          sync.Mutex
}

// 20 OMIT

// NewSessStore creates a SessStore.
// gcInterval defines how often garbage collection will be run.
func NewSessStore(gcInterval time.Duration) *SessStore {
	// 30 OMIT
	s := SessStore{}
	s.m = make(map[string]Session)
	s.l = sync.Mutex{}
	s.GCInterval = gcInterval
	return &s
}

//40 OMIT

// Set writes a new session record into the SessStore.
// The session expires after sess.dur.
func (s *SessStore) Set(sess Session) {
	//50 OMIT
	s.l.Lock()
	s.m[sess.ID] = sess
	s.l.Unlock()
}

//60 OMIT

// Get checks if key is present in SessStore.
// Returns true if found and not expired. At the same time extends the expiry.
// Expired sessions are deleted.
// Returns false if not found.
func (s *SessStore) Get(key string) (Session, bool) {
	//70 OMIT
	ret := false
	s.l.Lock()
	sess, ok := s.m[key]
	s.l.Unlock()
	if ok {
		if time.Now().After(sess.Expires) {
			s.Delete(key)
		} else {
			sess.Expires = time.Now().Add(sess.dur)
			s.Set(sess)
			ret = true
		}
	}
	return sess, ret
}

//80 OMIT

// Delete deletes a session entry in the SessStore.
func (s *SessStore) Delete(key string) {
	//90 OMIT
	s.l.Lock()
	delete(s.m, key)
	s.l.Unlock()
}

//100 OMIT

// GC explicitly triggers garbage collection on SessStore.
// Garbage collection is normally handled by a background goroutine.
func (s *SessStore) GC() {
	//110 OMIT
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.Expires) {
			s.Delete(k)
		}
	}
}

type userRec struct {
	ID, Email, HashedPw string
}

func newUserRec(id, email, pw string) *userRec {
	u := userRec{}
	u.ID = id
	u.Email = email
	hpw, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("bcrypt:", err)
	}
	u.HashedPw = string(hpw)
	return &u
}

func randID(n int) string {
	b := make([]byte, n, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// AutoExpireCache is a cache with expiry deadline.
type AutoExpireCache interface {
	Set(id string, value []byte, expires time.Time)
	Get(id string) ([]byte, bool)
}

// NewMemCache creates a memory based AutoExpireCache.
func NewMemCache() *MemCache {
	m := MemCache{}
	x := sync.Mutex{}
	m.x = &x
	m.h = make(map[string][]byte)
	m.t = make(map[string]time.Time)
	m.stop = make(chan bool)
	(&m).garbageCollect()
	return &m
}

// MemCache is a memory based AutoExpireCache
type MemCache struct {
	x    *sync.Mutex
	h    map[string][]byte
	t    map[string]time.Time
	stop chan bool
}

// Set a value
func (m *MemCache) Set(id string, value []byte, expires time.Time) {
	m.x.Lock()
	m.h[id] = value
	m.t[id] = expires
	m.x.Unlock()
}

// Stop the MemCache
func (m *MemCache) Stop() {
	m.stop <- true
}
func (m *MemCache) garbageCollect() {
	tckr := time.NewTicker(time.Second)
	go func() {
		for {
			select {
			case <-tckr.C:
				cutOff := time.Now()
				m.x.Lock()
				for k, v := range m.t {
					if cutOff.After(v) {
						delete(m.t, k)
						delete(m.h, k)
					}
				}
				m.x.Unlock()
			case <-m.stop:
				tckr.Stop()
				break
			}
		}
	}()
}

// Get a value
func (m MemCache) Get(id string) ([]byte, bool) {
	m.x.Lock()
	val, ok := m.h[id]
	m.x.Unlock()
	return val, ok
}

func envDflt(enVar, dflt string) (ret string) {
	ret = dflt
	if os.Getenv(enVar) != "" {
		ret = os.Getenv(enVar)
	}
	return
}

//120 OMIT

// IsAuthorized checks if client browser sent a valid session cookie with the request.
// Not or not yet authorized users are usually redirected to the login page.
func IsAuthorized(r *http.Request, ckName string, s *SessStore) (Session, bool) {
	auth := false
	//300 OMIT
	ck, err := r.Cookie(ckName)
	//310 OMIT
	var sess Session
	if err == nil { // cookie found
		sess, auth = s.Get(ck.Value) // valid session found
	}
	return sess, auth
}

//130 OMIT

//140 OMIT

// UserRec format
type UserRec struct {
	ID           string // user authenticates against an ID (eg. tomSawyer)
	Email        string
	Groups       []string // groups dictate authorization limits
	HashedPasswd string
}

//150 OMIT

// 160 OMIT

// UserDB is implemented with boltdb.
// Remember to call UserDB.Close() to close the database.
type UserDB struct {
	db *bolt.DB
}

// 170 OMIT
//180 OMIT

// NewUserDB opens a UserDB,
// creates it if it does not already exist.
func NewUserDB(fn string) *UserDB {
	//190 OMIT
	udb := UserDB{}
	db, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	udb.db = db
	udb.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte("UserDB"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	return &udb
}

//200 OMIT

// Close closes the database.
func (u *UserDB) Close() {
	//210 OMIT
	log.Println("userdb closed.")
	u.db.Close()
}

//220 OMIT

// Set writes 2 entries to the DB.
// {key: rec.ID value: rec} and {key: rec.Email value: rec}
// Thus we can Get by ID or Email.
func (u *UserDB) Set(rec UserRec) error {
	//230 OMIT
	return u.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("UserDB"))
		value, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		err = b.Put([]byte(rec.ID), value)
		if err != nil {
			return err
		}

		err = b.Put([]byte(rec.Email), value)
		if err != nil {
			return err
		}

		return err
	})
}

//240 OMIT

// Get returns value and bool ok = true if found.
func (u UserDB) Get(key string) (v []byte, ok bool) {
	//250 OMIT
	u.db.View(func(tx *bolt.Tx) error {
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte("UserDB"))
		v = b.Get([]byte(key))
		if v != nil {
			ok = true
		}
		return nil
	})
	return
}

//246 OMIT

//ChkPasswd checks if passwd matches for given id or email.
func (u UserDB) ChkPasswd(id, passwd string) (matched bool) {
	//248 OMIT
	u.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("UserDB"))
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		usrRec := UserRec{}
		err := json.Unmarshal(v, &usrRec)
		if err != nil {
			log.Fatal(err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(usrRec.HashedPasswd), []byte(passwd))
		if err == nil {
			matched = true
		}
		return nil
	})
	return
}

//260 OMIT

// List lists the keys (IDs and Emails) in the DB.
func (u UserDB) List() []string {
	//270 OMIT
	var v []string
	u.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("UserDB"))
		c := b.Cursor()
		for key, _ := c.First(); key != nil; key, _ = c.Next() {
			v = append(v, string(key))
		}
		return nil
	})

	return v
}

// main function -----------------------------------------
func main() {
	port := ":" + envDflt("PORT", "8123")
	ckName := envDflt("COOKIE_NAME", "gerbau")
	sessLenS := envDflt("SESSION_LENGTH", "1800") // seconds
	sessLen, err := strconv.Atoi(sessLenS)
	if err != nil {
		log.Fatal(err)
	}

	rand.Seed(time.Now().UnixNano())
	//380 OMIT
	log.Println("server starting.")
	udb := NewUserDB("user.db")
	udb.Set(UserRec{ID: "abc", Email: "abc@example.com",
		HashedPasswd: "$2a$10$DG7kMMIfD6SNk58/byDZ.OLiGbe3lRZK0Mc6hF/VMIVPAwCvIN69K"}) //passwd is abc
	defer udb.Close()
	//390 OMIT
	t := template.Must(template.New("").ParseGlob("tpl/**/*"))
	sessStore := NewSessStore(5 * time.Minute)
	log.Println("templates parsed")

	authMux := http.NewServeMux()
	authMux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		currSess, _ := IsAuthorized(r, ckName, sessStore)
		t.ExecuteTemplate(w, "secret/main", map[string]interface{}{"sess": currSess})
	})
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./html"))))
	//280 OMIT
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		currSess, auth := IsAuthorized(r, ckName, sessStore)
		if r.URL.Path == "/" {
			t.ExecuteTemplate(w, "index/main", map[string]interface{}{
				"title": "MyTitle",
				"body":  template.HTML(`<h1 class="blue">I am /</h1>`),
				"sess":  currSess,
			})
		} else {
			if !auth {
				http.Redirect(w, r, "/login", http.StatusFound)
			} else {
				authMux.ServeHTTP(w, r)
			}
		}
	})
	//290 OMIT

	//340 OMIT
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		currSess, _ := IsAuthorized(r, ckName, sessStore)
		if r.Method == "GET" {
			t.ExecuteTemplate(w, "login/main", map[string]interface{}{"sess": currSess})
		} else {
			matched := udb.ChkPasswd(r.FormValue("id"), r.FormValue("passwd"))
			if matched {
				id := randID(24)
				http.SetCookie(w, &http.Cookie{Name: ckName, Value: id, MaxAge: 24 * 3600})
				currSess := Session{id, r.FormValue("id"), time.Now().Add(time.Duration(sessLen) * time.Second), time.Duration(sessLen) * time.Second}
				sessStore.Set(currSess)
				t.ExecuteTemplate(w, "login/post", map[string]interface{}{
					"status": matched,
					"sess":   currSess})
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
		}
	})
	//350 OMIT
	//360 OMIT
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		currSess, _ := IsAuthorized(r, ckName, sessStore)
		t.ExecuteTemplate(w, "about/main", map[string]interface{}{"sess": currSess})
	})
	//370 OMIT

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		ck, _ := r.Cookie(ckName)
		sessStore.Delete(ck.Value)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	log.Fatal(http.ListenAndServe(port, mux))
}
