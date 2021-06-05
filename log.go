package regex

import (
	"log"
	"os"
)

var logs = log.New(os.Stderr, "regex", log.LstdFlags|log.Llongfile)
