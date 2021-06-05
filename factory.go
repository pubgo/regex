package regex

import (
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

	defer func() {
		if err := recover(); err != nil {
			logs.Fatalf("%v \n", err)
		}
	}()

	reg.reg = reg.Build()
	factories[name] = reg
}

func Has(name string) bool {
	var reg, ok = factories[name]
	return ok || reg.reg == nil
}

func Get(name string) *regexp.Regexp {
	var reg, ok = factories[name]
	if !ok {
		if Debug {
			logs.Printf("%s not found", name)
		}
		return nil
	}

	return reg.reg
}

func Each(fn func(name string, reg *Regex)) {
	defer func() {
		if err := recover(); err != nil {
			logs.Fatalf("%v \n", err)
		}
	}()

	for k, v := range factories {
		fn(k, v)
	}
}
