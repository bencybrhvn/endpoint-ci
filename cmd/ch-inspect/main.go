// Command ch-inspect is the local content-inspection CLI for the PoC.
//
//	ch-inspect --rules config/rules.json --file <path>     scan one file
//	ch-inspect --rules config/rules.json --report          rule compatibility report
//	ch-inspect --rules config/rules.json --bench <dir>     latency p50/p95/p99 over a dir
//	ch-inspect --rules config/rules.json --scan <dir>      profile real files (recursive)
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyberhaven/endpoint-ci/internal/engine"
	"github.com/cyberhaven/endpoint-ci/internal/extract"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
)

func main() {
	rulesPath := flag.String("rules", "config/rules.json", "path to rules.json")
	file := flag.String("file", "", "file to inspect")
	report := flag.Bool("report", false, "print rule compatibility report and exit")
	bench := flag.String("bench", "", "benchmark: scan every file in a (flat) directory")
	scan := flag.String("scan", "", "profile: recursively inspect real files under a directory")
	maxFileMB := flag.Int("max-file-mb", 16, "size gate: files larger than this are head/tail inspected only")
	maxReadMB := flag.Int("max-read-mb", 50, "skip files larger than this (avoid reading huge files whole)")
	topN := flag.Int("top", 10, "show this many slowest files in --scan")
	maxFiles := flag.Int("max-files", 0, "cap files processed in --scan (0 = all)")
	includeHidden := flag.Bool("include-hidden", false, "include dot-directories (e.g. .git) in --scan")
	isolate := flag.Bool("isolate", true, "--scan: inspect each file in a child process with an RSS/time watchdog (crash-safe)")
	rssCapMB := flag.Int("rss-cap-mb", 512, "--scan isolated: kill a child exceeding this RSS")
	fileTimeout := flag.Int("file-timeout-sec", 8, "--scan isolated: kill a child running longer than this")
	csvPath := flag.String("csv", "", "write per-file results to this CSV path (--scan)")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile to this path")
	memProfile := flag.String("memprofile", "", "write a heap profile to this path")
	flag.Parse()

	db, err := rules.Load(*rulesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load rules:", err)
		os.Exit(1)
	}
	cfg := extract.Config{MaxFileBytes: *maxFileMB << 20}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cpuprofile:", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	switch {
	case *report:
		printReport(db)
	case *bench != "":
		runBench(db, *bench, cfg)
	case *scan != "":
		self, _ := os.Executable()
		runScan(db, cfg, scanOpts{dir: *scan, top: *topN, maxFiles: *maxFiles,
			maxReadBytes: int64(*maxReadMB) << 20, csvPath: *csvPath, includeHidden: *includeHidden,
			isolate: *isolate, rssCapMB: *rssCapMB, timeout: time.Duration(*fileTimeout) * time.Second,
			self: self, rulesPath: *rulesPath, maxFileMB: *maxFileMB})
	case *file != "":
		v, err := engine.InspectFile(*file, db, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "inspect file:", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(out))
	default:
		flag.Usage()
		os.Exit(2)
	}

	if *memProfile != "" {
		f, err := os.Create(*memProfile)
		if err == nil {
			runtime.GC()
			pprof.WriteHeapProfile(f)
			f.Close()
		}
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

type scanOpts struct {
	dir           string
	top           int
	maxFiles      int
	maxReadBytes  int64
	csvPath       string
	includeHidden bool
	isolate       bool
	rssCapMB      int
	timeout       time.Duration
	self          string
	rulesPath     string
	maxFileMB     int
}

type fileResult struct {
	path    string
	size    int64
	ftype   string
	verdict string
	micros  int64
	partial bool
	short   bool
}

// runScan recursively inspects real files and reports a real-world profile:
// latency percentiles, throughput, verdict + file-type breakdowns, the slowest
// files, and process memory impact.
func runScan(db *rules.DB, cfg extract.Config, o scanOpts) {
	var results []fileResult
	var totalBytes int64
	var skippedLarge, errored, killed int

	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	wallStart := time.Now()

	walkErr := filepath.WalkDir(o.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable dir/file — skip
		}
		if d.IsDir() {
			// skip dot-directories (.git, .cache, …) unless asked to include them
			if !o.includeHidden && path != o.dir && len(d.Name()) > 1 && d.Name()[0] == '.' {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if o.maxFiles > 0 && len(results) >= o.maxFiles {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if o.maxReadBytes > 0 && info.Size() > o.maxReadBytes {
			skippedLarge++
			return nil
		}
		if os.Getenv("CH_VERBOSE") != "" {
			fmt.Fprintln(os.Stderr, path)
		}
		var v engine.Verdict
		var ierr error
		if o.isolate {
			v, ierr = inspectIsolated(o, path)
		} else {
			v, ierr = engine.InspectFile(path, db, cfg)
		}
		totalBytes += info.Size()
		if ierr != nil {
			// child killed (OOM/timeout) or unreadable — record as escalate so it's visible.
			killed++
			results = append(results, fileResult{path, info.Size(), "(killed)", engine.Escalate,
				o.timeout.Microseconds(), false, false})
			return nil
		}
		results = append(results, fileResult{path, info.Size(), v.FileType, v.Disposition,
			v.ScanMicros, v.Partial, v.ShortCircuit})
		return nil
	})
	_ = errored
	wall := time.Since(wallStart)
	if walkErr != nil {
		fmt.Fprintln(os.Stderr, "walk:", walkErr)
	}
	if len(results) == 0 {
		fmt.Println("no files inspected")
		return
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	// aggregates
	verdicts := map[string]int{}
	types := map[string]int{}
	var partial, short int
	durs := make([]time.Duration, len(results))
	var sumMicros int64
	for i, r := range results {
		verdicts[r.verdict]++
		types[r.ftype]++
		if r.partial {
			partial++
		}
		if r.short {
			short++
		}
		durs[i] = time.Duration(r.micros) * time.Microsecond
		sumMicros += r.micros
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	pct := func(q float64) time.Duration { return durs[int(float64(len(durs)-1)*q)] }

	n := len(results)
	mbTotal := float64(totalBytes) / (1 << 20)
	scanSecs := float64(sumMicros) / 1e6

	fmt.Printf("=== endpoint-ci real-world scan ===\n")
	fmt.Printf("root:            %s\n", o.dir)
	fmt.Printf("files inspected: %d   (skipped >%.0fMB: %d, killed OOM/timeout: %d)\n",
		n, float64(o.maxReadBytes)/(1<<20), skippedLarge, killed)
	if o.isolate {
		fmt.Printf("isolation:       on (child per file, RSS cap %dMB, timeout %v)\n", o.rssCapMB, o.timeout)
	}
	fmt.Printf("total content:   %.1f MB\n", mbTotal)
	fmt.Printf("wall time:       %v   (inspect-only CPU: %.2fs)\n", wall.Round(time.Millisecond), scanSecs)
	if scanSecs > 0 {
		fmt.Printf("throughput:      %.1f MB/s, %.0f files/s (inspect-only)\n", mbTotal/scanSecs, float64(n)/scanSecs)
	}

	fmt.Printf("\nper-file latency:\n")
	fmt.Printf("  mean %v  p50 %v  p90 %v  p95 %v  p99 %v  max %v\n",
		(time.Duration(sumMicros/int64(n)) * time.Microsecond).Round(time.Microsecond),
		pct(0.50).Round(time.Microsecond), pct(0.90).Round(time.Microsecond),
		pct(0.95).Round(time.Microsecond), pct(0.99).Round(time.Microsecond), durs[n-1].Round(time.Microsecond))

	fmt.Printf("\nverdicts:  ")
	for _, k := range []string{engine.Allow, engine.Escalate, engine.Block} {
		fmt.Printf("%s=%d (%.0f%%)  ", k, verdicts[k], 100*float64(verdicts[k])/float64(n))
	}
	fmt.Printf("\nshort-circuited: %d   partial (size gate): %d\n", short, partial)

	fmt.Printf("\nfile types:\n")
	for _, kv := range sortedCounts(types) {
		fmt.Printf("  %-12s %d\n", kv.k, kv.v)
	}

	fmt.Printf("\nslowest %d files:\n", min(o.top, n))
	slow := make([]fileResult, len(results))
	copy(slow, results)
	sort.Slice(slow, func(i, j int) bool { return slow[i].micros > slow[j].micros })
	for i := 0; i < o.top && i < len(slow); i++ {
		r := slow[i]
		fmt.Printf("  %7.2f ms  %-9s %-9s %8.0f KB  %s\n",
			float64(r.micros)/1000, r.verdict, r.ftype, float64(r.size)/1024, r.path)
	}

	fmt.Printf("\nmemory impact:\n")
	fmt.Printf("  Go heap in use:  %.1f MB\n", float64(memAfter.HeapAlloc)/(1<<20))
	fmt.Printf("  Go heap sys:     %.1f MB\n", float64(memAfter.HeapSys)/(1<<20))
	fmt.Printf("  total allocated: %.1f MB over scan   GCs: %d\n",
		float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/(1<<20), memAfter.NumGC-memBefore.NumGC)
	if rss := maxRSSBytes(); rss > 0 {
		fmt.Printf("  peak RSS:        %.1f MB\n", float64(rss)/(1<<20))
	}

	if o.csvPath != "" {
		if err := writeCSV(o.csvPath, results); err != nil {
			fmt.Fprintln(os.Stderr, "csv:", err)
		} else {
			fmt.Printf("\nper-file CSV written: %s\n", o.csvPath)
		}
	}
}

// inspectIsolated runs `ch-inspect --file <path>` as a child process with an RSS
// watchdog + timeout, so a memory-bomb file (e.g. a malicious PDF) only kills the
// child. Per-file scan latency comes from the child's JSON (accurate, in-child).
func inspectIsolated(o scanOpts, path string) (engine.Verdict, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.self, "--rules", o.rulesPath, "--file", path,
		"--max-file-mb", strconv.Itoa(o.maxFileMB))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return engine.Verdict{}, err
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(150 * time.Millisecond)
		defer t.Stop()
		capBytes := int64(o.rssCapMB) << 20
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if cmd.Process != nil && rssBytes(cmd.Process.Pid) > capBytes {
					_ = cmd.Process.Kill()
				}
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		return engine.Verdict{}, err
	}
	var v engine.Verdict
	if e := json.Unmarshal(out.Bytes(), &v); e != nil {
		return engine.Verdict{}, e
	}
	return v, nil
}

// rssBytes returns a process's resident set size via ps (darwin/linux).
func rssBytes(pid int) int64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	kb, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return int64(kb) * 1024
}

type kv struct {
	k string
	v int
}

func sortedCounts(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	return out
}

// maxRSSBytes returns peak resident set size in bytes (best-effort, cross-platform).
func maxRSSBytes() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	// Linux reports KB, macOS/BSD report bytes.
	if runtime.GOOS == "linux" {
		return int64(ru.Maxrss) * 1024
	}
	return int64(ru.Maxrss)
}

func writeCSV(path string, rs []fileResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"path", "bytes", "type", "verdict", "micros", "partial", "short_circuit"})
	for _, r := range rs {
		w.Write([]string{r.path, fmt.Sprint(r.size), r.ftype, r.verdict,
			fmt.Sprint(r.micros), fmt.Sprint(r.partial), fmt.Sprint(r.short)})
	}
	return nil
}

func runBench(db *rules.DB, dir string, cfg extract.Config) {
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
		path := filepath.Join(dir, e.Name())
		if fi, err := os.Stat(path); err == nil {
			totalBytes += int(fi.Size())
		}
		files++
		start := time.Now()
		engine.InspectFile(path, db, cfg)
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
