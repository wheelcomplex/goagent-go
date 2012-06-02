package main

import (
	"fmt"
	"io"
	"log"
	"path"
	"runtime"
)

func paniconerr(err error) {
	if err != nil {
		panic(err)
	}
}

func logonerr(err error) {
	if err != nil {
		_, filepath, line, ok := runtime.Caller(1)
		if ok {
			_, filename := path.Split(filepath)
			log.Printf("File: %s Line: %d\n\t%s\n", filename, line, err)
		} else {
			log.Printf("%s\n", err)
		}
	}
}

func exitonerr(err error) {
	if err != nil {
		_, filepath, line, ok := runtime.Caller(1)
		fmt.Println()
		if ok {
			_, filename := path.Split(filepath)
			log.Fatalf("File: %s Line: %d\n\t%s\n", filename, line, err)
		} else {
			log.Fatalf("%s\n", err)
		}
	}
}

type closeWrap struct {
	closer io.Closer
	io.ReadCloser
}

func (wrap *closeWrap) Close() error {
	wrap.ReadCloser.Close()
	return wrap.closer.Close()
}
