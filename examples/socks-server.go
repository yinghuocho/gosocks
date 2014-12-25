package main

import (
	"time"
	"github.com/yinghuocho/gosocks"
)

func main() {
	srv := gosocks.NewServer("", time.Minute)
	srv.ListenAndServe()
}