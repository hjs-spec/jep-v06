package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: jep-validate <validate|validate-chain|syntax|canonicalize> <file> [--keys file] [--mode archival|acceptance] [--trust-profile none|inline|kid-prefix] [--aud audience] [--replay-cache file]")
		os.Exit(2)
	}
	command, path := os.Args[1], os.Args[2]
	o := defaults()
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	keys := ""
	assumption := "partial"
	fs.StringVar(&keys, "keys", "", "trusted JWK file")
	fs.StringVar(&o.Mode, "mode", o.Mode, "verification mode")
	fs.StringVar(&o.Trust, "trust-profile", o.Trust, "local actor binding profile")
	fs.StringVar(&o.Audience, "aud", "", "expected audience")
	fs.StringVar(&o.Cache, "replay-cache", "", "persistent nonce cache")
	fs.Int64Var(&o.Now, "now", o.Now, "current Unix time")
	fs.Int64Var(&o.MaxAge, "max-age", 300, "freshness seconds")
	fs.Int64Var(&o.FutureSkew, "max-future-skew", 60, "future skew seconds")
	fs.StringVar(&assumption, "log-assumption", "partial", "partial or complete")
	fs.Parse(os.Args[3:])
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o.Keys, err = keyFile(keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var output any
	valid := false
	switch command {
	case "validate":
		r := eventResult(raw, o)
		output = r
		valid = r.Valid
	case "validate-chain":
		r := chainBytes(raw, o, assumption)
		output = r
		valid = r.Valid
	case "syntax":
		r := validateBytes(raw)
		output = r
		valid = r.Valid
	case "canonicalize":
		v, e := parseJSONUnique(raw)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		b, e := canonical(v)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
	if !valid {
		os.Exit(1)
	}
}
