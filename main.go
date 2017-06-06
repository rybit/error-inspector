package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var dbName string
var colName string
var user string
var pass string
var port int
var servers []string

var out string
var poolSize int
var reportInterval int
var limit int

var enableTLS bool
var certFile string
var keyFile string
var caFiles []string

func main() {
	if err := rootCmd().Execute(); err != nil {
		log.Fatal(err)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Run: run,
	}

	root.Flags().StringVar(&dbName, "db", "test", "the db to query")
	root.Flags().StringVarP(&colName, "col", "c", "blobs", "the collection to query")
	root.Flags().StringVarP(&user, "user", "U", "", "the query to connect on")
	root.Flags().StringVarP(&pass, "pass", "P", "", "the password to use")
	root.Flags().StringSliceVarP(&servers, "server", "S", []string{"mongo.lo"}, "a server to connect to")
	root.Flags().IntVarP(&port, "port", "p", 27017, "the port to connect on")

	root.Flags().IntVarP(&poolSize, "size", "s", 10, "the number of workers to use to process results")
	root.Flags().IntVarP(&reportInterval, "report", "i", 10000, "the number of blobs to check in on")
	root.Flags().StringVarP(&out, "out", "o", "error_blobs_", "the file to write results to")

	root.Flags().IntVar(&limit, "limit", 0, "a limit for the number of blobs")

	// tls
	root.Flags().BoolVar(&enableTLS, "tls", false, "if we should use TLS")
	root.Flags().StringSliceVar(&caFiles, "ca", []string{}, "a ca file to use")
	root.Flags().StringVar(&keyFile, "key", "", "the .pem file to use")
	root.Flags().StringVar(&certFile, "cert", "", "the .pem file to use")
	return root
}

func run(cmd *cobra.Command, args []string) {
	if err := validate(cmd); err != nil {
		panic(err)
	}

	log.Println("Starting to connect to DB")

	// connect to mongo
	db := connect()
	log.Println("Connected to DB")
	col := db.C(colName)
	query := bson.M{"error": bson.M{"$exists": true}}

	// query for all the errors
	total, err := col.Find(query).Count()
	if err != nil {
		panic(errors.Wrap(err, "failed to query for count of error"))
	}

	log.Printf("There are %d blobs to read", total)

	consumed := 0
	reasons := map[string]int{}
	work, wg := startWorkerPool()
	q := col.Find(query)
	if limit > 0 {
		q = q.Limit(limit)
	}
	iter := q.Iter()
	start := time.Now()
	next := new(Blob)
	for iter.Next(next) {
		reasons[next.Error] += 1

		work <- next
		consumed += 1
		if consumed%reportInterval == 0 {
			log.Printf("Consumed %d/%d (%.02f%%) blobs\n", consumed, total, float32(consumed)/float32(total)*100.0)
		}
		next = new(Blob)
	}

	close(work)
	log.Printf("Finished consuming %d blobs - waiting for it to write to disk\n", consumed)
	wg.Wait()
	log.Printf("Finished writing out blobs to disk in %s. %d reasons discovered\n", time.Since(start).String(), len(reasons))
	fmt.Printf("count\treason\n")
	for reason, count := range reasons {
		fmt.Printf("%d\t%s\n", count, reason)
	}
}

type Blob struct {
	SHA   string `bson:"sha"`
	Error string `bson:"error"`
}

func startWorkerPool() (chan *Blob, *sync.WaitGroup) {
	work := make(chan *Blob, 1000)
	wg := new(sync.WaitGroup)

	for i := 0; i < poolSize; i++ {
		wg.Add(1)
		go consume(work, wg, out+strconv.Itoa(i))
	}

	return work, wg
}

func consume(work chan *Blob, wg *sync.WaitGroup, name string) {
	f, err := os.Create(name)
	if err != nil {
		panic(errors.Wrap(err, fmt.Sprintf("Failed to create file %s", name)))
	}
	w := bufio.NewWriter(f)

	defer func() {
		w.Flush()
		f.Close()
		wg.Done()
	}()
	for blob := range work {
		w.WriteString(fmt.Sprintf("%s %s\n", blob.SHA, blob.Error))
	}

	log.Println("Shutting down worker")
}

func connect() *mgo.Database {
	info := &mgo.DialInfo{
		Addrs:   servers,
		Timeout: time.Second * 60,
	}

	if enableTLS {
		log.Print("Enabling TLS")
		tlsConfig := getTLSConfig()
		info.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
			return tls.Dial("tcp", addr.String(), tlsConfig)
		}
	}

	sess, err := mgo.DialWithInfo(info)
	if err != nil {
		panic(errors.Wrap(err, "Failed to dial MongoDB"))
	}

	return sess.DB(dbName)
}

func validate(cmd *cobra.Command) error {
	errors := []string{}
	if enableTLS {
		if len(caFiles) == 0 {
			errors = append(errors, "Must specify at least on CA file with TLS")
		}
		if keyFile == "" {
			errors = append(errors, "Must specify a key file")
		}
		if certFile == "" {
			errors = append(errors, "Must specify a cert file")
		}
	}

	if poolSize <= 0 {
		errors = append(errors, "Must have positive number of workers")
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, ","))
	}
	return nil
}

func getTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	for _, caFile := range caFiles {
		caData, err := ioutil.ReadFile(caFile)
		if err != nil {
			panic(errors.Wrap(err, fmt.Sprintf("Failed to read CA file %s", caFile)))
		}

		if !pool.AppendCertsFromPEM(caData) {
			panic(fmt.Errorf("Failed to add CA cert at %s", caFile))
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(errors.Wrap(err, "Failed to load the X509 pair"))
	}

	tlsConfig := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig
}
