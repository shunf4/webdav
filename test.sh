#!/bin/bash
PATH=/usr/lib/go-1.13/bin/:$PATH
go build
./webdav -c ./test.config.yml
