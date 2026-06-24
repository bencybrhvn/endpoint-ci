// Command ch-inspect is the local content-inspection CLI for the PoC.
//
//	ch-inspect --rules config/rules.json --file <path>     scan one file
//	ch-inspect --rules config/rules.json --report          rule compatibility report
//	ch-inspect --rules config/rules.json --bench <dir>     latency p50/p95/p99 over a dir
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cyberhaven/endpoint-ci/internal/engine"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
)

func main() {
	rulesPath := flag.String("rules", "config/rules.json", "path to rules.json")
	file := flag.String("file", "", "file to inspect")
	report := flag.Bool("report", false, "print rule compatibility report and exit")
	bench := flag.String("bench", "", "benchmark: scan every file in this directory")
	flag.Parse()

	db, err := rules.Load(*rulesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load rules:", err)
		os.Exit(1)
	}

	switch {
	case *report:
		printReport(db)
	case *bench != "":
		runBench(db, *bench)
	case *file != "":
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read file:", err)
			os.Exit(1)
		}
		v := engine.Inspect(*file, string(b), db)
		out, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(out))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func printReport(db *rules.DB) {
	capable, cloud := 0, 0
	for _, d := range db.Detectors {
		if d.Compat == rules.CloudOnly {
			cloud++
		} else {
			capable++
		}
	}
	fmt.Println("Rule compilation report")
	fmt.Printf("  Detectors:        %d\n", len(db.Detectors))
	fmt.Printf("  LOCAL_CAPABLE:    %d\n", capable)
	fmt.Printf("  CLOUD_ONLY:       %d\n", cloud)
	fmt.Printf("  Profiles:         %d\n\n", len(db.Profiles))
	for _, d := range db.Detectors {
		kind := d.Kind
		if kind == "" {
			kind = "regex"
		}
		fmt.Printf("  %-16s %-14s %-8s patterns=%d validators=%v\n", d.ID, d.Compat, kind, len(d.PatternStrs), d.Validators)
	}
	if cloud > 0 {
		fmt.Println("\nCLOUD_ONLY (not evaluated locally):")
		for _, d := range db.Detectors {
			if d.Compat == rules.CloudOnly {
				fmt.Printf("  - %s\n", d.ID)
			}
		}
	}
}

func runBench(db *rules.DB, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench dir:", err)
		os.Exit(1)
	}
	var durs []time.Duration
	var totalBytes int
	files := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) == ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		files++
		totalBytes += len(b)
		text := string(b)
		start := time.Now()
		engine.Inspect(e.Name(), text, db)
		durs = append(durs, time.Since(start))
	}
	if len(durs) == 0 {
		fmt.Println("no files to benchmark")
		return
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	p := func(q float64) time.Duration { return durs[int(float64(len(durs)-1)*q)] }
	var sum time.Duration
	for _, d := range durs {
		sum += d
	}
	fmt.Printf("Benchmark over %d files (%d bytes total)\n", files, totalBytes)
	fmt.Printf("  mean: %v\n", sum/time.Duration(len(durs)))
	fmt.Printf("  p50:  %v\n", p(0.50))
	fmt.Printf("  p95:  %v\n", p(0.95))
	fmt.Printf("  p99:  %v\n", p(0.99))
	fmt.Printf("  max:  %v\n", durs[len(durs)-1])
}
