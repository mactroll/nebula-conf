package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/golang/gddo/httputil/header"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"gopkg.in/yaml.v2"
)

type ConfigFile struct {
	AuthConfig struct {
		DiscoveryURL string `yaml:"discoveryurl`
		ClientID     string `yaml:"clientid"`
		ReidrectURI  string `yaml:"redirecturi"`
		CAURL        string `yaml:"caurl"`
	} `yaml:"auth"`
	CAConfig struct {
		CAKeyFile  string `yaml:"cakeyfile`
		CACertFile string `yaml:"cacertfile`
		JWKSURL    string `yaml:"jwksurl"`
	} `yaml:"ca"`
}

type IssueCertRequest struct {
	Token  string
	PubKey string
}

type CustomClaims struct {
	*jwt.Claims
	// additional claims apart from standard claims
	email map[string]interface{}
}

// NewConfig returns a new decoded Config struct
func NewConfig(configPath string) (*ConfigFile, error) {
	// Create config structure
	config := &ConfigFile{}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (string, error) {
	// String that contains the configured configuration path
	var configPath string

	// Set up a CLI flag called "-config" to allow users
	// to supply the configuration file
	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")

	// Actually parse the flags
	flag.Parse()

	// Validate the path first
	if err := ValidateConfigPath(configPath); err != nil {
		return "", err
	}

	// Return the configuration path
	return configPath, nil
}

// Handle the JSON POST

func issueCertCreate(w http.ResponseWriter, r *http.Request, config ConfigFile) {

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			msg := "Content-Type header is not application/json"
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}
	}

	// Use http.MaxBytesReader to enforce a maximum read of 1MB from the
	// response body. A request body larger than that will now result in
	// Decode() returning a "http: request body too large" error.
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Setup the decoder and call the DisallowUnknownFields() method on it.
	// This will cause Decode() to return a "json: unknown field ..." error
	// if it encounters any extra unexpected fields in the JSON. Strictly
	// speaking, it returns an error for "keys which do not match any
	// non-ignored, exported fields in the destination".
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var certRequest IssueCertRequest

	err := dec.Decode(&certRequest)

	if err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError

		switch {
		// Catch any syntax errors in the JSON and send an error message
		// which interpolates the location of the problem to make it
		// easier for the client to fix.
		case errors.As(err, &syntaxError):
			msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
			http.Error(w, msg, http.StatusBadRequest)

		// In some circumstances Decode() may also return an
		// io.ErrUnexpectedEOF error for syntax errors in the JSON. There
		// is an open issue regarding this at
		// https://github.com/golang/go/issues/25956.
		case errors.Is(err, io.ErrUnexpectedEOF):
			msg := fmt.Sprintf("Request body contains badly-formed JSON")
			http.Error(w, msg, http.StatusBadRequest)

		// Catch any type errors, like trying to assign a string in the
		// JSON request body to a int field in our Person struct. We can
		// interpolate the relevant field name and position into the error
		// message to make it easier for the client to fix.
		case errors.As(err, &unmarshalTypeError):
			msg := fmt.Sprintf("Request body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
			http.Error(w, msg, http.StatusBadRequest)

		// Catch the error caused by extra unexpected fields in the request
		// body. We extract the field name from the error message and
		// interpolate it in our custom error message. There is an open
		// issue at https://github.com/golang/go/issues/29035 regarding
		// turning this into a sentinel error.
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
			http.Error(w, msg, http.StatusBadRequest)

		// An io.EOF error is returned by Decode() if the request body is
		// empty.
		case errors.Is(err, io.EOF):
			msg := "Request body must not be empty"
			http.Error(w, msg, http.StatusBadRequest)

		// Catch the error caused by the request body being too large. Again
		// there is an open issue regarding turning this into a sentinel
		// error at https://github.com/golang/go/issues/30715.
		case err.Error() == "http: request body too large":
			msg := "Request body must not be larger than 1MB"
			http.Error(w, msg, http.StatusRequestEntityTooLarge)

		// Otherwise default to logging the error and sending a 500 Internal
		// Server Error response.
		default:
			log.Println(err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	email, tokenerr := verifyToken(certRequest.Token, config)
	if tokenerr != nil {
		log.Println(tokenerr)
		return
	}

	log.Println(email)
	log.Println(certRequest.PubKey)
	//err = os.WriteFile("/tmp/dat1", []byte(certRequest.PubKey), 0644)
}

// Get JWKS for validating tokens

func fetchJwks(jwksURL string) (*jose.JSONWebKeySet, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create jwks request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch jwks: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response code")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	jwks := jose.JSONWebKeySet{}

	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal jwks into struct: %w", err)
	}

	return &jwks, nil
}

func verifyToken(bearerToken string, config ConfigFile) (string, error) {

	// Parse bearer token from request
	token, err := jwt.ParseSigned(bearerToken)
	if err != nil {
		return "", fmt.Errorf("could not parse Bearer token: %w", err)
	}

	// Get jwks
	jsonWebKeySet, err := fetchJwks(config.CAConfig.JWKSURL)
	if err != nil {
		return "", fmt.Errorf("could not load JWKS: %w", err)
	}

	out := make(map[string]interface{})
	if err := token.Claims(jsonWebKeySet, &out); err != nil {
		panic(err)
	}

	// Get claims out of token (validate signature while doing that)
	claims := CustomClaims{}
	err = token.Claims(jsonWebKeySet, &claims)
	if err != nil {
		return "", fmt.Errorf("could not retrieve claims: %w", err)
	}

	// Validate claims (issuer, expiresAt, etc.)
	err = claims.Validate(jwt.Expected{})
	if err != nil {
		return "", fmt.Errorf("could not validate claims: %w", err)
	}

	if !claims.Audience.Contains(config.AuthConfig.ClientID) {
		return "", errors.New("Wrong audience for token") //fmt.Errorf("Wrong audience for token")
	}

	log.Println("ID Token is valid!")

	return out["email"].(string), nil
}

// make a temp directory, pass in the pubkey, sign in, get the cert back

func signPubKey(pubKey string, name string, config ConfigFile) *string {

	tempDir, err := ioutil.TempDir("", "nebula-temp*")
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer os.RemoveAll(tempDir)

	pubKeyFile, err := ioutil.TempFile(tempDir, "pubkey*")
	if err != nil {
		log.Fatal(err)
		return nil
	}

	log.Println(pubKeyFile)

	cmd := exec.Command("nebula-cert sign -")

	err = cmd.Run()

	if err != nil {
		log.Fatal(err)
	}
	return nil
}

// NewRouter generates the router used in the HTTP Server
func NewRouter(config ConfigFile) *http.ServeMux {
	// Create router and define routes and return that router
	router := http.NewServeMux()

	// this just lets us know things are alive

	router.HandleFunc("/welcome", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
	})

	// this writes out the nebula configuration

	router.HandleFunc("/.well-known/nebula-configuration", func(w http.ResponseWriter, r *http.Request) {
		jsonReturn, err := json.Marshal(config.AuthConfig)
		if err == nil {
			fmt.Fprintf(w, "%s\n", jsonReturn)
		}
	})

	// handle a request for a signed certificate using an id token

	router.HandleFunc("/issuecert", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprintf(w, "nothing to see here")
		case "POST":
			issueCertCreate(w, r, config)
		}
	})

	return router
}

func (config ConfigFile) run() {
	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

	// Define server options
	server := &http.Server{
		Addr:         "127.0.0.1:8000",
		Handler:      NewRouter(config),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Handle ctrl+c/ctrl+x interrupt
	signal.Notify(runChan, os.Interrupt)

	// Alert the user that the server is starting
	log.Printf("Server is starting on %s\n", server.Addr)

	// Run the server on a new goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				// Normal interrupt operation, ignore
			} else {
				log.Fatalf("Server failed to start due to err: %v", err)
			}
		}
	}()

	// Block on this channel listeninf for those previously defined syscalls assign
	// to variable so we can let the user know why the server is shutting down
	interrupt := <-runChan

	// Set up a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30,
	)
	defer cancel()

	// If we get one of the pre-prescribed syscalls, gracefully terminate the server
	// while alerting the user
	log.Printf("Server is shutting down due to %+v\n", interrupt)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server was unable to gracefully shutdown due to err: %+v", err)
	}
}

func main() {
	// Generate our config based on the config supplied
	// by the user in the flags
	cfgPath, err := ParseFlags()
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := NewConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("DiscoveryURL: %v", cfg.AuthConfig.DiscoveryURL)

	// Run the server
	cfg.run()
}
