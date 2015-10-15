package main

import (
	"github.com/yinghuocho/gosocks"
	"time"
)

func main() {
	srv := gosocks.NewBasicServer(":10800", time.Minute)
	srv.ListenAndServe()
}
