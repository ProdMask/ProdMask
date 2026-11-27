package sqldump

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The errors of Open. None holds the path, nor anything from the file.
var (
	ErrDirectory  = errors.New("the dump is a directory; this format comes from a single file")
	ErrStdin      = errors.New("standard input isn't allowed here; give a file")
	ErrNotFound   = errors.New("the dump file doesn't exist")
	ErrPermission = errors.New("the dump file can't be read: permission denied")
	ErrOpen       = errors.New("the dump file couldn't be opened")
	ErrBadGzip    = errors.New("the dump starts like gzip but can't be decompressed")
	ErrZstd       = errors.New("the dump is compressed with zstd; decompress it to a file first, for example with zstd -d FILE, and give that file")
	ErrXZ         = errors.New("the dump is compressed with xz; decompress it to a file first, for example with xz -d FILE, and give that file")
	ErrBzip2      = errors.New("the dump is compressed with bzip2; decompress it to a file first, for example with bzip2 -d FILE, and give that file")
	ErrZip        = errors.New("the dump is a zip archive; extract it to a file first, for example with unzip FILE, and give that file")
	Err7z         = errors.New("the dump is a 7z archive; extract it to a file first, for example with 7z x FILE, and give that file")
)

// Info describes an opened dump.
type Info struct {
	// Compression is "gzip", or "" for plain text.
	Compression string
	// Size and ModTime are the file's, for the check that it didn't change
	// between two passes. Size is -1 for standard input.
	Size    int64
	ModTime time.Time

	read *atomic.Int64
}

// BytesRead is how many bytes were read from the file so far, compressed.
func (i Info) BytesRead() int64 {
	if i.read == nil {
		return 0
	}
	return i.read.Load()
}

type refusedMagic struct {
	magic []byte
	err   error
}

var refused = []refusedMagic{
	{[]byte{0x28, 0xb5, 0x2f, 0xfd}, ErrZstd},
	{[]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, ErrXZ},
	{[]byte{'B', 'Z', 'h'}, ErrBzip2},
	{[]byte{'P', 'K', 3, 4}, ErrZip},
	{[]byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, Err7z},
}

// meter counts the bytes read through it.
type meter struct {
	r io.Reader
	n *atomic.Int64
}

func (m meter) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	m.n.Add(int64(n))
	return n, err
}

type openFile struct {
	*bufio.Reader
	closers []io.Closer
}

func (f *openFile) Close() error {
	var first error
	for _, c := range f.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Open opens a dump for reading. "-" is standard input, when allowStdin is
// set. A gzip file is decompressed, members and all; zstd, xz, bzip2, zip and
// 7z are refused, and so is a directory. A UTF-8 byte-order mark is skipped.
func Open(path string, allowStdin bool) (io.ReadCloser, Info, error) {
	var info Info
	var f io.Reader
	var closer io.Closer = nopCloser{}
	if path == "-" {
		if !allowStdin {
			return nil, info, ErrStdin
		}
		f = os.Stdin
		info.Size = -1
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, info, openError(err)
		}
		st, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, info, ErrOpen
		}
		if st.IsDir() {
			file.Close()
			return nil, info, ErrDirectory
		}
		info.Size, info.ModTime = st.Size(), st.ModTime()
		f, closer = file, file
	}
	info.read = new(atomic.Int64)
	br := bufio.NewReaderSize(meter{f, info.read}, readBufSize)
	head, _ := br.Peek(8)
	for _, rf := range refused {
		if bytes.HasPrefix(head, rf.magic) {
			closer.Close()
			return nil, info, rf.err
		}
	}
	out := &openFile{closers: []io.Closer{closer}}
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			closer.Close()
			return nil, info, ErrBadGzip
		}
		info.Compression = "gzip"
		ar := newAheadReader(zr)
		ar.noWait = path == "-"
		out.closers = append([]io.Closer{ar, zr}, out.closers...)
		out.Reader = bufio.NewReaderSize(ar, readBufSize)
	} else {
		out.Reader = br
	}
	if b, _ := out.Peek(3); bytes.Equal(b, bom) {
		out.Discard(3)
	}
	return out, info, nil
}

// aheadReader reads its source in a goroutine, a few buffers ahead of its
// reader, so that decompressing a file and reading its statements use two
// processors and the file is read as fast as the slower of the two.
type aheadReader struct {
	full chan aheadBuf
	free chan []byte
	quit chan struct{}
	done chan struct{}
	once sync.Once
	cur  []byte
	last []byte
	err  error

	// noWait makes Close return without waiting for the goroutine, which
	// can be stuck in a read of standard input that never comes.
	noWait bool
}

type aheadBuf struct {
	b   []byte
	err error
}

const (
	aheadSize  = 256 << 10
	aheadDepth = 4
)

func newAheadReader(r io.Reader) *aheadReader {
	a := &aheadReader{full: make(chan aheadBuf, aheadDepth), free: make(chan []byte, aheadDepth+2),
		quit: make(chan struct{}), done: make(chan struct{})}
	for range aheadDepth + 2 {
		a.free <- make([]byte, aheadSize)
	}
	go a.run(r)
	return a
}

func (a *aheadReader) run(r io.Reader) {
	defer close(a.done)
	for {
		var b []byte
		select {
		case b = <-a.free:
		case <-a.quit:
			return
		}
		n := 0
		var err error
		for n < len(b) && err == nil {
			var m int
			m, err = r.Read(b[n:])
			n += m
		}
		select {
		case a.full <- aheadBuf{b[:n], err}:
		case <-a.quit:
			return
		}
		if err != nil {
			return
		}
	}
}

func (a *aheadReader) Read(p []byte) (int, error) {
	for len(a.cur) == 0 {
		if a.err != nil {
			return 0, a.err
		}
		if a.last != nil {
			a.free <- a.last
			a.last = nil
		}
		ab := <-a.full
		a.cur, a.last, a.err = ab.b, ab.b[:cap(ab.b)], ab.err
	}
	n := copy(p, a.cur)
	a.cur = a.cur[n:]
	return n, nil
}

// Close stops the goroutine; the source is closed by its owner.
func (a *aheadReader) Close() error {
	a.once.Do(func() { close(a.quit) })
	if !a.noWait {
		<-a.done
	}
	return nil
}

func openError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ErrNotFound
	case errors.Is(err, fs.ErrPermission):
		return ErrPermission
	}
	return ErrOpen
}
