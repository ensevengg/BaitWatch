package main

import (
	"flag"
	"fmt"
	"strings"
)

func main() {
	sep := flag.String("sep", ",", "separator")
	flag.Parse()
	for _, line := range strings.Split(readAll(), "\n") {
		fmt.Println(strings.Join(strings.Split(line, *sep), " | "))
	}
}

func readAll() string {
	var b []byte
	fmt.Scan(&b)
	return string(b)
}
