package main

import (
	"time"
	"github.com/yinghuocho/gosocks"
)

func main() {
	srv := gosocks.NewServer(":10800", time.Minute)
	srv.ListenAndServe()
}
