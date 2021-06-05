package regex

import (
	"log"
	"regexp"
)

type Regex struct {
	Desc  string
	Build func() *regexp.Regexp
	reg   *regexp.Regexp
}

var factories = make(map[string]*Regex)

func Register(name string, reg *Regex) {
	var _, ok = factories[name]
	if ok {
		logs.Fatalf("%s already exists\n", name)
	}

	factories[name] = reg
}

func Get(name string) *regexp.Regexp {
	var reg, ok = factories[name]
	if !ok {
		return nil
	}

	return reg.reg
}

func Each(fn func(name string, reg *Regex)) {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("%v \n", err)
		}
	}()

	for k, v := range factories {
		fn(k, v)
	}
}
