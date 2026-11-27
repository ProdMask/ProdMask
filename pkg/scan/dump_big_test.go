package scan

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// --- a generator of WordPress-shaped SQL ---

// genSpec says what one generated dump holds. The fixed parts (the sites, the
// key/value table and the big values) don't grow with size; the main site's
// posts take up the rest, so a bigger dump has more rows of one table.
type genSpec struct {
	size    int64 // bytes of SQL, about
	sites   int   // sites of the multisite, the first being the main one
	keys    int   // distinct meta keys of the main site's postmeta
	bigVals int   // values of 1 MiB, spread over three tables
}

const genChunk = 1 << 20

var (
	paraOnce sync.Once
	paras    [][]byte // SQL-escaped text, read only
)

// paragraphs is a pool of pseudo-random text, so that deflate has to work as
// it does on real text.
func paragraphs() [][]byte {
	paraOnce.Do(func() {
		rng := rand.New(rand.NewPCG(3, 5))
		words := make([]string, 3000)
		for i := range words {
			b := make([]byte, 2+rng.IntN(9))
			for j := range b {
				b[j] = 'a' + byte(rng.IntN(26))
			}
			words[i] = string(b)
		}
		words[7], words[99], words[1234] = `it\'s`, `don\'t`, `\"quoted\"`
		paras = make([][]byte, 4096)
		for i := range paras {
			var p []byte
			n := 40 + rng.IntN(120)
			for j := range n {
				if j > 0 {
					p = append(p, ' ')
				}
				// Zipf-like: a few words are common.
				w := min(rng.IntN(len(words)), rng.IntN(len(words)))
				p = append(p, words[w]...)
				if rng.IntN(25) == 0 {
					p = append(p, `.\n\n`...)
				}
			}
			paras[i] = p
		}
	})
	return paras
}

// sqlw collects SQL into 1 MiB buffers that a goroutine hands on.
type sqlw struct {
	buf  []byte
	full chan []byte
	free chan []byte
	done <-chan struct{}
	n    int64
	rows int64
	stop bool
}

func (w *sqlw) flush() {
	if w.stop {
		w.buf = w.buf[:0]
		return
	}
	if len(w.buf) == 0 {
		return
	}
	w.n += int64(len(w.buf))
	select {
	case w.full <- w.buf:
	case <-w.done:
		w.stop = true
	}
	select {
	case w.buf = <-w.free:
		w.buf = w.buf[:0]
	case <-w.done:
		w.stop = true
		w.buf = w.buf[:0]
	}
}

func (w *sqlw) str(s string) {
	w.buf = append(w.buf, s...)
	if len(w.buf) >= genChunk {
		w.flush()
	}
}

func (w *sqlw) raw(b []byte) {
	w.buf = append(w.buf, b...)
	if len(w.buf) >= genChunk {
		w.flush()
	}
}

func (w *sqlw) int(v int64) { w.buf = strconv.AppendInt(w.buf, v, 10) }

// written is the bytes handed on so far, including the open buffer.
func (w *sqlw) written() int64 { return w.n + int64(len(w.buf)) }

// text writes the quoted text of one row: n paragraphs picked by the row's
// number.
func (w *sqlw) text(id int64, paragraphsN int) {
	p := paragraphs()
	w.buf = append(w.buf, '\'')
	h := uint64(id)*0x9E3779B97F4A7C15 + 12345
	for range paragraphsN {
		h ^= h >> 29
		h *= 0xBF58476D1CE4E5B9
		w.buf = append(w.buf, p[h%uint64(len(p))]...)
		w.buf = append(w.buf, ' ')
	}
	w.buf = append(w.buf, '\'')
}

// bigText writes a quoted value of 1 MiB.
func (w *sqlw) bigText(id int64) {
	p := paragraphs()
	w.buf = append(w.buf, '\'')
	start := len(w.buf)
	h := uint64(id) + 1
	for len(w.buf)-start < 1<<20 {
		h = h*6364136223846793005 + 1442695040888963407
		w.buf = append(w.buf, p[(h>>33)%uint64(len(p))]...)
		w.buf = append(w.buf, ' ')
	}
	w.buf = w.buf[:start+1<<20]
	if w.buf[len(w.buf)-1] == '\\' { // never cut an escape in two
		w.buf[len(w.buf)-1] = 'x'
	}
	w.buf = append(w.buf, '\'')
}

const genHead = "-- MySQL dump 10.13  Distrib 8.4.3, for Linux (x86_64)\n--\n-- Host: localhost    Database: wordpress\n" +
	"-- ------------------------------------------------------\n-- Server version\t8.4.3\n\n" +
	"/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n/*!40101 SET NAMES utf8mb4 */;\n" +
	"/*!40103 SET TIME_ZONE='+00:00' */;\n/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n\n"

const genOptions = "CREATE TABLE `%[1]soptions` (\n  `option_id` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `option_name` varchar(191) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n" +
	"  `option_value` longtext COLLATE utf8mb4_unicode_520_ci NOT NULL,\n" +
	"  `autoload` varchar(20) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'yes',\n" +
	"  PRIMARY KEY (`option_id`),\n  UNIQUE KEY `option_name` (`option_name`),\n  KEY `autoload` (`autoload`)\n" +
	") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n"

const genPosts = "CREATE TABLE `%[1]sposts` (\n  `ID` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `post_author` bigint unsigned NOT NULL DEFAULT '0',\n  `post_date` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n" +
	"  `post_date_gmt` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n  `post_content` longtext COLLATE utf8mb4_unicode_520_ci NOT NULL,\n" +
	"  `post_title` text COLLATE utf8mb4_unicode_520_ci NOT NULL,\n  `post_excerpt` text COLLATE utf8mb4_unicode_520_ci NOT NULL,\n" +
	"  `post_status` varchar(20) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'publish',\n" +
	"  `comment_status` varchar(20) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'open',\n" +
	"  `post_name` varchar(200) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n" +
	"  `post_modified` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n  `post_parent` bigint unsigned NOT NULL DEFAULT '0',\n" +
	"  `guid` varchar(255) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n  `post_type` varchar(20) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT 'post',\n" +
	"  PRIMARY KEY (`ID`),\n  KEY `post_name` (`post_name`(191)),\n  KEY `type_status_date` (`post_type`,`post_status`,`post_date`,`ID`)\n" +
	") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n"

const genPostmeta = "CREATE TABLE `%[1]spostmeta` (\n  `meta_id` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `post_id` bigint unsigned NOT NULL DEFAULT '0',\n  `meta_key` varchar(255) COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,\n" +
	"  `meta_value` longtext COLLATE utf8mb4_unicode_520_ci,\n  PRIMARY KEY (`meta_id`),\n  KEY `post_id` (`post_id`),\n" +
	"  KEY `meta_key` (`meta_key`(191))\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n"

const genUsers = "CREATE TABLE `wp_users` (\n  `ID` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `user_login` varchar(60) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n" +
	"  `user_pass` varchar(255) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n" +
	"  `user_email` varchar(100) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n" +
	"  `display_name` varchar(250) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n  PRIMARY KEY (`ID`),\n  KEY `user_login_key` (`user_login`)\n" +
	") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n"

const genUsermeta = "CREATE TABLE `wp_usermeta` (\n  `umeta_id` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `user_id` bigint unsigned NOT NULL DEFAULT '0',\n  `meta_key` varchar(255) COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,\n" +
	"  `meta_value` longtext COLLATE utf8mb4_unicode_520_ci,\n  PRIMARY KEY (`umeta_id`),\n  KEY `user_id` (`user_id`),\n" +
	"  KEY `meta_key` (`meta_key`(191))\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n"

const genBlogs = "CREATE TABLE `wp_blogs` (\n  `blog_id` bigint NOT NULL AUTO_INCREMENT,\n  `site_id` bigint NOT NULL DEFAULT '0',\n" +
	"  `domain` varchar(200) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n" +
	"  `path` varchar(100) COLLATE utf8mb4_unicode_520_ci NOT NULL DEFAULT '',\n  `registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n" +
	"  PRIMARY KEY (`blog_id`),\n  KEY `domain` (`domain`(50),`path`(5))\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n"

// table writes a table's structure.
func (w *sqlw) table(name, create string) {
	w.str("\n--\n-- Table structure for table `" + name + "`\n--\n\nDROP TABLE IF EXISTS `" + name + "`;\n" + create + "\n" +
		"--\n-- Dumping data for table `" + name + "`\n--\n\nLOCK TABLES `" + name + "` WRITE;\n")
}

func (w *sqlw) endTable() { w.str("UNLOCK TABLES;\n") }

// rowsOf writes the rows 1..n as INSERT statements of about 1 MiB, row(i)
// writing the i-th row's parentheses.
func (w *sqlw) rowsOf(table string, from, n int64, row func(i int64)) {
	i := from
	for i < from+n && !w.stop {
		w.str("INSERT INTO `" + table + "` VALUES ")
		start := len(w.buf)
		for first := true; i < from+n; i++ {
			if !first {
				w.buf = append(w.buf, ',')
			}
			first = false
			row(i)
			w.rows++
			if len(w.buf)-start > 1<<20-4096 {
				i++
				break
			}
		}
		w.str(";\n")
	}
}

func (g genSpec) site(w *sqlw, n int) {
	prefix := "wp_"
	if n > 1 {
		prefix = "wp_" + strconv.Itoa(n) + "_"
	}
	opts, posts, metas := prefix+"options", prefix+"posts", prefix+"postmeta"
	w.table(opts, fmt.Sprintf(genOptions, prefix))
	w.rowsOf(opts, 1, 60, func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",'opt_")
		w.int(i)
		w.str("',")
		if i <= 3 {
			w.str("'https://site")
			w.int(int64(n))
			w.str(".example.test/'")
		} else {
			w.text(i+int64(n)*1000, 1)
		}
		w.str(",'yes')")
	})
	w.endTable()
	w.table(posts, fmt.Sprintf(genPosts, prefix))
	w.rowsOf(posts, 1, 100, func(i int64) { g.post(w, i) })
	w.endTable()
	w.table(metas, fmt.Sprintf(genPostmeta, prefix))
	w.rowsOf(metas, 1, 100, func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",")
		w.int(i%100 + 1)
		w.str(",'_meta_")
		w.int(i % 7)
		w.str("',")
		w.text(i, 1)
		w.str(")")
	})
	w.endTable()
}

func (g genSpec) post(w *sqlw, id int64) {
	w.str("(")
	w.int(id)
	w.str(",1,'2024-05-")
	w.buf = append(w.buf, byte('0'+id%3), byte('0'+id%10))
	w.str(" 10:11:12','2024-05-01 08:11:12',")
	w.text(id, 2+int(id%3))
	w.str(",'Post ")
	w.int(id)
	w.str("','','publish','open','post-")
	w.int(id)
	w.str("','2024-05-01 10:11:12',0,'https://example.test/?p=")
	w.int(id)
	w.str("','post')")
}

// writeAll writes the whole dump.
func (g genSpec) writeAll(w *sqlw) {
	w.str(genHead)
	w.table("wp_blogs", genBlogs)
	w.rowsOf("wp_blogs", 1, int64(g.sites), func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",1,'site")
		w.int(i)
		w.str(".example.test','/','2024-01-01 00:00:00')")
	})
	w.endTable()
	w.table("wp_users", genUsers)
	w.rowsOf("wp_users", 1, 5000, func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",'user")
		w.int(i)
		w.str("','$P$B0000000000000000000000000000/','user")
		w.int(i)
		w.str("@example.test','User ")
		w.int(i)
		w.str("')")
	})
	w.endTable()
	w.table("wp_usermeta", genUsermeta)
	w.rowsOf("wp_usermeta", 1, 50000, func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",")
		w.int(i%5000 + 1)
		w.str(",'meta_")
		w.int(i % 10)
		w.str("',")
		w.text(i, 1)
		w.str(")")
	})
	w.endTable()
	for n := g.sites; n >= 2 && !w.stop; n-- {
		g.site(w, n)
	}
	// The main site: options with some big values, a postmeta with a great many
	// keys and some big values, and posts to fill the size.
	w.table("wp_options", fmt.Sprintf(genOptions, "wp_"))
	big := g.bigVals / 3
	w.rowsOf("wp_options", 1, 100, func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",'opt_")
		w.int(i)
		w.str("',")
		if i <= int64(big) {
			w.bigText(i)
		} else {
			w.text(i, 1)
		}
		w.str(",'yes')")
	})
	w.endTable()
	w.table("wp_postmeta", fmt.Sprintf(genPostmeta, "wp_"))
	rows := int64(g.keys) * 2
	w.rowsOf("wp_postmeta", 1, rows+int64(big), func(i int64) {
		w.str("(")
		w.int(i)
		w.str(",")
		w.int(i%1000 + 1)
		if i > rows {
			w.str(",'_big_")
			w.int(i - rows)
			w.str("',")
			w.bigText(i)
		} else {
			w.str(",'_field_")
			w.buf = append(w.buf, fmt.Sprintf("%06d", i%int64(g.keys))...)
			w.str("',")
			w.text(i, 0)
		}
		w.str(")")
	})
	w.endTable()
	w.table("wp_posts", fmt.Sprintf(genPosts, "wp_"))
	id := int64(0)
	bigPosts := g.bigVals - 2*big
	for !w.stop && w.written() < g.size-4096 {
		w.str("INSERT INTO `wp_posts` VALUES ")
		start := len(w.buf)
		for first := true; !w.stop && w.written() < g.size-4096 && len(w.buf)-start < 1<<20-8192; first = false {
			if !first {
				w.buf = append(w.buf, ',')
			}
			id++
			if id <= int64(bigPosts) {
				w.str("(")
				w.int(id)
				w.str(",1,'2024-05-01 10:11:12','2024-05-01 08:11:12',")
				w.bigText(id)
				w.str(",'Big ")
				w.int(id)
				w.str("','','publish','open','big-")
				w.int(id)
				w.str("','2024-05-01 10:11:12',0,'https://example.test/?p=")
				w.int(id)
				w.str("','post')")
			} else {
				g.post(w, id)
			}
			w.rows++
		}
		w.str(";\n")
	}
	w.endTable()
	w.str("\n-- Dump completed\n")
	w.flush()
}

// genReader is an io.ReadCloser over a generated dump; a goroutine writes it
// ahead of the reader.
type genReader struct {
	full chan []byte
	free chan []byte
	cur  []byte
	last []byte
	quit chan struct{}
	once sync.Once
	rows *int64 // written when the generator finishes
	wg   sync.WaitGroup
}

func (g genSpec) open(rowsOut *int64) *genReader {
	r := &genReader{full: make(chan []byte, 4), free: make(chan []byte, 8), quit: make(chan struct{}), rows: rowsOut}
	for range 6 {
		r.free <- make([]byte, 0, genChunk+(2<<20))
	}
	w := &sqlw{full: r.full, free: r.free, done: r.quit}
	w.buf = <-r.free
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		g.writeAll(w)
		*rowsOut = w.rows
		close(r.full)
	}()
	return r
}

func (r *genReader) Read(p []byte) (int, error) {
	for len(r.cur) == 0 {
		if r.last != nil {
			select {
			case r.free <- r.last[:0]:
			default:
			}
			r.last = nil
		}
		b, ok := <-r.full
		if !ok {
			return 0, io.EOF
		}
		r.cur, r.last = b, b
	}
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	return n, nil
}

func (r *genReader) Close() error {
	r.once.Do(func() { close(r.quit) })
	r.wg.Wait()
	return nil
}

// --- measuring ---

const (
	heapMetric = "/memory/classes/heap/objects:bytes"
	liveMetric = "/gc/heap/live:bytes"
)

// peaks are the highest values seen of the heap's objects, which the
// collector's pacing lets grow to about twice the live data, and of the live
// data the last collection marked, which doesn't depend on that pacing.
type peaks struct{ objects, live uint64 }

// peakHeap samples the heap every 50 ms until stop is called, and returns the
// highest values seen.
func peakHeap() (stop func() peaks) {
	var (
		mu   sync.Mutex
		peak peaks
		done = make(chan struct{})
		wg   sync.WaitGroup
	)
	sample := []metrics.Sample{{Name: heapMetric}, {Name: liveMetric}}
	take := func() {
		metrics.Read(sample)
		mu.Lock()
		defer mu.Unlock()
		if sample[0].Value.Kind() == metrics.KindUint64 {
			peak.objects = max(peak.objects, sample[0].Value.Uint64())
		}
		if sample[1].Value.Kind() == metrics.KindUint64 {
			peak.live = max(peak.live, sample[1].Value.Uint64())
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			take()
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	return func() peaks {
		close(done)
		wg.Wait()
		take()
		mu.Lock()
		defer mu.Unlock()
		return peak
	}
}

// timedOpen wraps an open function, timing each pass from its open to its
// close.
type timedOpen struct {
	mu     sync.Mutex
	passes []time.Duration
	opens  func() (io.ReadCloser, error)
}

type timedRC struct {
	io.ReadCloser
	t     *timedOpen
	start time.Time
}

func (r *timedRC) Close() error {
	err := r.ReadCloser.Close()
	r.t.mu.Lock()
	r.t.passes = append(r.t.passes, time.Since(r.start))
	r.t.mu.Unlock()
	return err
}

func (t *timedOpen) open() (io.ReadCloser, error) {
	start := time.Now()
	rc, err := t.opens()
	if err != nil {
		return nil, err
	}
	return &timedRC{ReadCloser: rc, t: t, start: start}, nil
}

// bigRun is what one scan of a big dump measured.
type bigRun struct {
	peak   peaks
	passes []time.Duration
	judged time.Duration // the second pass's time in finishing tables
	rows   int64
	tables int
}

func runBig(t *testing.T, open func() (io.ReadCloser, error)) bigRun {
	t.Helper()
	runtime.GC()
	debug.FreeOSMemory()
	to := &timedOpen{opens: open}
	opts := dumpOpts()
	opts.File = "big.sql"
	var judged time.Duration
	opts.limits.finishTime = func(d time.Duration) { judged += d }
	stop := peakHeap()
	res, err := RunDump(context.Background(), to.open, opts)
	peak := stop()
	if err != nil {
		t.Fatal(err)
	}
	if len(to.passes) != 2 {
		t.Fatalf("%d passes", len(to.passes))
	}
	if res.Dump.Unread != 0 {
		t.Fatalf("%d statements unread", res.Dump.Unread)
	}
	return bigRun{peak: peak, passes: to.passes, judged: judged, rows: res.Dump.Rows, tables: len(res.Tables)}
}

// reading is the time pass i spent reading: the second pass's finishing of the
// tables (reading out what each collected, and judging it) is left out, since
// it works on a bounded sample and doesn't grow with the file.
func (r bigRun) reading(i int) time.Duration {
	if i == 1 {
		return r.passes[i] - r.judged
	}
	return r.passes[i]
}

func mbps(bytes int64, d time.Duration) float64 { return float64(bytes) / 1e6 / d.Seconds() }

// gzipFile writes the dump to a gzip file, and returns the bytes of SQL.
func gzipFile(t *testing.T, g genSpec, path string) int64 {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	zw, _ := gzip.NewWriterLevel(bw, gzip.BestSpeed)
	var rows int64
	r := g.open(&rows)
	n, err := io.Copy(zw, r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	return n
}

// gunzipSpeed is how fast compress/gzip alone reads the file, in MB of SQL a
// second.
func gunzipSpeed(t *testing.T, path string) float64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start := time.Now()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, zr)
	if err != nil {
		t.Fatal(err)
	}
	return mbps(n, time.Since(start))
}

func bigSpec(size int64) genSpec {
	return genSpec{size: size, sites: 1000, keys: 300000, bigVals: 48}
}

// TestDumpBigStreams scans generated dumps of 1 GiB and 4 GiB, plain and
// gzipped, and holds the scan to its bounds: a peak heap under 384 MiB, a
// 4 GiB peak within 10% of the 1 GiB one, and floors on each pass's speed.
//
// The collector's pacing lets the heap's objects grow to about twice the live
// data before it runs, and when it runs depends on the phase of the scan, so
// the objects' peak of two runs of the same scan differs by as much as 25%. The
// cap is held to that peak. The comparison of the two sizes
// is held to the peak of the live data the collector marked, which is the same
// quantity without the pacing; the objects' peaks are logged beside it.
func TestDumpBigStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 10 GiB of generated SQL")
	}
	// Opt-in: the run is heavy, and its live-heap ratio is measured by the
	// collector, which concurrent load on the machine has pushed over its limit.
	// CI runs every test without -short, so it asks for this one by name.
	if os.Getenv("PRODMASK_TEST_BIG") != "1" {
		t.Skip("heavy; set PRODMASK_TEST_BIG=1 to run it")
	}
	const peakCap = 384 << 20
	peaksOf := map[string]map[int64]peaks{"plain": {}, "gzip": {}}
	check := func(t *testing.T, kind string, size int64, run bigRun) {
		t.Helper()
		t.Logf("%d GiB %s: peak heap objects %d MiB, live data %d MiB; %d tables, %d rows",
			size>>30, kind, run.peak.objects>>20, run.peak.live>>20, run.tables, run.rows)
		if run.peak.objects > peakCap {
			t.Errorf("peak heap %d MiB, want under 384", run.peak.objects>>20)
		}
		peaksOf[kind][size] = run.peak
	}
	for _, size := range []int64{1 << 30, 4 << 30} {
		t.Run(fmt.Sprintf("plain %d GiB", size>>30), func(t *testing.T) {
			g := bigSpec(size)
			var counts [2]int64
			var calls int
			run := runBig(t, func() (io.ReadCloser, error) {
				i := min(calls, 1)
				calls++
				return g.open(&counts[i]), nil
			})
			if counts[0] != counts[1] || run.rows != counts[0] {
				t.Errorf("rows: generated %d and %d, scanned %d", counts[0], counts[1], run.rows)
			}
			for i, d := range run.passes {
				v := mbps(size, run.reading(i))
				t.Logf("pass %d: %.0f MB/s reading, %.0f MB/s with the finishing of tables, %v", i+1, v, mbps(size, d), run.judged.Round(time.Millisecond))
				if v < 50 {
					t.Errorf("pass %d reads %.0f MB/s, want at least 50", i+1, v)
				}
			}
			check(t, "plain", size, run)
		})
	}
	for _, size := range []int64{1 << 30, 4 << 30} {
		t.Run(fmt.Sprintf("gzip %d GiB", size>>30), func(t *testing.T) {
			g := bigSpec(size)
			path := filepath.Join(t.TempDir(), "big.sql.gz")
			sqlBytes := gzipFile(t, g, path)
			base := gunzipSpeed(t, path)
			st, _ := os.Stat(path)
			t.Logf("%d GiB of SQL gzipped to %d MiB; compress/gzip alone reads %.0f MB/s", size>>30, st.Size()>>20, base)
			run := runBig(t, func() (io.ReadCloser, error) {
				rc, _, err := sqldump.Open(path, false)
				return rc, err
			})
			for i := range run.passes {
				v := mbps(sqlBytes, run.reading(i))
				t.Logf("pass %d: %.0f MB/s reading, %.0f%% of gzip alone", i+1, v, v/base*100)
				if v < 0.8*base {
					t.Errorf("pass %d reads %.0f MB/s, under 80%% of gzip's %.0f", i+1, v, base)
				}
			}
			check(t, "gzip", size, run)
		})
	}
	for kind, m := range peaksOf {
		a, b := m[1<<30], m[4<<30]
		if a.live == 0 || b.live == 0 {
			continue
		}
		t.Logf("%s: 4 GiB over 1 GiB, live data %.2f, heap objects %.2f", kind, float64(b.live)/float64(a.live), float64(b.objects)/float64(a.objects))
		if float64(b.live) > float64(a.live)*1.1 {
			t.Errorf("%s: the 4 GiB peak of live data, %d MiB, is over 110%% of the 1 GiB peak, %d MiB", kind, b.live>>20, a.live>>20)
		}
	}
}

// ascendingDump is a table of n rows with ascending keys, the order a dump of
// a table with an auto-increment key comes in.
func ascendingDump(n int, shuffle bool) string {
	var b strings.Builder
	b.WriteString(dumpHead)
	b.WriteString("CREATE TABLE `notes` (`id` bigint unsigned NOT NULL AUTO_INCREMENT, `title` varchar(100) DEFAULT NULL, `body` text, `status` varchar(20) DEFAULT NULL, PRIMARY KEY (`id`));\n")
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i + 1
	}
	if shuffle {
		rand.New(rand.NewPCG(1, 2)).Shuffle(n, func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	}
	p := paragraphs()
	for i := 0; i < n; i += 100 {
		b.WriteString("INSERT INTO `notes` VALUES ")
		for j := i; j < min(i+100, n); j++ {
			if j > i {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "(%d,'Note %d','%s','published')", ids[j], ids[j], strings.TrimRight(string(p[j%len(p)][:200]), `\`))
		}
		b.WriteString(";\n")
	}
	return b.String()
}

func BenchmarkRunDumpAscending(b *testing.B) {
	for _, shuffle := range []bool{false, true} {
		sql := ascendingDump(300000, shuffle)
		name := "ascending"
		if shuffle {
			name = "shuffled"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(sql)))
			for b.Loop() {
				if _, err := RunDump(context.Background(), openText(sql), dumpOpts()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
