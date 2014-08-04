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

type fileInput struct {
	fileName *string
	data     io.ReadCloser
}
type hashResult struct {
	fileName *string
	result   []byte
}

func main() {
	handleFlags()
	in := make(chan fileInput, *fConcurrent*2)
	out := make(chan hashResult, *fConcurrent*2)

	//Start opening files for processing
	go func() {
		if flag.NArg() == 0 {
			in <- fileInput{nil, os.Stdin}
		} else {
			for i := range flag.Args() {
				file := flag.Arg(i)
				if stream, err := os.Open(file); err == nil {
					in <- fileInput{&file, stream}
				} else {
					fmt.Println(err.Error())
				}
			}
		}
		close(in)
	}()

	//Hash the files that have been opened for processing
	go func() {
		defer close(out)
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
				fmt.Fprintf(os.Stderr, "I don't know how to compute a %s hash!", *fHash)
				return
			}
			wg.Add(1)
			go digester(&wg, &hash, out, in)
		}
		wg.Wait()
	}()

	//Display the hashing results
	for curResult := range out {
		if curResult.fileName == nil {
			fmt.Printf("%0x\n", curResult.result)
		} else {
			fmt.Printf("%0x  %s\n", curResult.result, *curResult.fileName)
		}
	}
}

func handleFlags() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s v1.0 Copyright (c) 2014, Gregory L. Dietsche.\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage of %s: [OPTION]... [FILE]...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *fConcurrent <= 0 {
		*fConcurrent = 1
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
}

func digester(wg *sync.WaitGroup, h *hash.Hash, out chan hashResult, streams chan fileInput) {
	for stream := range streams {
		(*h).Reset()

		io.Copy(*h, stream.data)
		stream.data.Close()

		out <- hashResult{stream.fileName, (*h).Sum(nil)}
	}
	wg.Done()
}
