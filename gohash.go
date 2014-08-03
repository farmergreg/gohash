package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
)

var fHash = flag.String("h", "sha256", "valid hashes: md5, sha1, sha224, sha256, sha384, sha512")
var fConcurrent = flag.Int("j", runtime.NumCPU()*2, "Maximum number of files processed concurrently.")
var fVersion = flag.Bool("version", false, "Print the version number and exit.")

type fileInput struct {
	index    int
	fileName string
	data     io.ReadCloser
}

func main() {
	flag.Parse()

	if *fVersion {
		fmt.Println("gosum v1.0")
		fmt.Println("Copyright (c) 2014, Gregory L. Dietsche.")
		return
	}
	if *fConcurrent <= 0 {
		*fConcurrent = 1
	}

	in := make(chan fileInput, *fConcurrent*10)
	out := make(chan *string, *fConcurrent*10)

	go func() {
		for i, file := range flag.Args() {
			stream, err := os.Open(file)
			if err == nil {
				in <- fileInput{i, file, stream}
			} else {
				fmt.Println(err.Error())
			}
		}
		close(in)
	}()

	go func() {
		var wg sync.WaitGroup
		*fHash = strings.ToLower(*fHash)
		for i := 0; i < *fConcurrent; i++ {
			var hash hash.Hash
			switch *fHash {
			case "md5":
				hash = md5.New()
			case "sha1":
				hash = sha1.New()
			case "sha224":
				hash = sha256.New224()
			case "sha256":
				hash = sha256.New()
			case "sha384":
				hash = sha512.New384()
			case "sha512":
				hash = sha512.New()
			default:
				panic("Unknown / unspported hash: " + *fHash)
			}
			wg.Add(1)
			go digester(&wg, &hash, out, in)
		}
		wg.Wait()
		close(out)
	}()

	for curResult := range out {
		fmt.Println(*curResult)
	}
}

func digester(wg *sync.WaitGroup, h *hash.Hash, out chan *string, streams chan fileInput) {
	for stream := range streams {
		(*h).Reset()

		io.Copy(*h, stream.data)
		stream.data.Close()

		message := fmt.Sprintf("%d %08x\t%s", stream.index, (*h).Sum(nil), stream.fileName)
		out <- &message
	}
	wg.Done()
}
