package geolocation

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// This file backs the IP2Location ASN + proxy range lookups with an on-disk,
// memory-mapped binary index instead of an in-RAM slice. The CSV is compiled once
// (on download/update) into two files next to it — "<name>.idx" (a sorted,
// fixed-width record table) and "<name>.strings" (a deduped string pool). At run
// time those files are mmap'd read-only, so lookups binary-search directly over
// the mapped pages and the process's resident memory stays tiny (the kernel pages
// the index in on demand and can reclaim it under pressure). Same lookup semantics
// as before — only the storage changed.
//
// .idx layout:  [magic "RIDX"(4)][version u16][recSize u16][count u32]  then
//               count records of recSize bytes: lo[16] hi[16] value[valSize].
// String values in a record are stored as u32 offsets into the .strings pool;
// each pooled string is [len u16][bytes]. Offset 0xFFFFFFFF means "no string".

const (
	maxRangeRows = 8_000_000 // defensive cap so a corrupt CSV can't blow up the build
	idxMagic     = "RIDX"
	idxVersion   = 1
	idxHeaderLen = 12
	noStrOff     = 0xFFFFFFFF
)

// asnVal / proxyVal are the per-range payloads (unchanged shape).
type asnVal struct {
	asn  uint32
	name string
}
type proxyVal struct {
	ptype    string
	usage    string
	threat   string
	fraud    uint8
	hasFraud bool
}

// proxyColumns holds the configurable CSV column indices for the richer proxy fields.
type proxyColumns struct {
	usageType int
	threat    int
	fraud     int
}

// codec[T] encodes/decodes a value into the fixed-width record's value bytes and a
// string pool. valSize is the fixed number of value bytes per record.
type codec[T any] struct {
	valSize int
	encode  func(dst []byte, v T, p *strPool)
	decode  func(val []byte, strs []byte) T
}

// rangeTable is a memory-mapped, sorted set of IP ranges searched by binary search.
// idx/strs are mmap'd read-only. A reload builds fresh files, opens a new mapping,
// and swaps under the write lock; a finalizer unmaps the old one once unreferenced.
type rangeTable[T any] struct {
	codec codec[T]

	mu           sync.RWMutex
	idx          []byte // mmap of .idx (header + records)
	strs         []byte // mmap of .strings
	count_       int
	recSize      int
	finalizerSet bool
}

func newRangeTable[T any](c codec[T]) *rangeTable[T] { return &rangeTable[T]{codec: c} }

// lookup returns the payload of the range containing ip, if any.
func (t *rangeTable[T]) lookup(ip string) (T, bool) {
	var zero T
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return zero, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.count_ == 0 {
		return zero, false
	}
	if v, ok := t.search(addr.As16()); ok {
		return v, true
	}
	// Some IP2Location IPv6 CSVs number IPv4 as the plain low 32 bits (::a.b.c.d).
	if addr.Is4() || addr.Is4In6() {
		v4 := addr.As4()
		var plain [16]byte
		copy(plain[12:], v4[:])
		if v, ok := t.search(plain); ok {
			return v, true
		}
	}
	return zero, false
}

// search binary-searches the mapped records for the range containing key. Caller holds RLock.
func (t *rangeTable[T]) search(key [16]byte) (T, bool) {
	var zero T
	i := sort.Search(t.count_, func(i int) bool {
		o := idxHeaderLen + i*t.recSize
		return bytes.Compare(t.idx[o:o+16], key[:]) > 0
	}) - 1
	if i < 0 {
		return zero, false
	}
	o := idxHeaderLen + i*t.recSize
	if bytes.Compare(key[:], t.idx[o+16:o+32]) <= 0 {
		return t.codec.decode(t.idx[o+32:o+t.recSize], t.strs), true
	}
	return zero, false
}

func (t *rangeTable[T]) count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count_
}

// iterate calls fn for every range (in sorted order) until fn returns false. Used by
// the ASN scans (expand-to-CIDRs, search). Caller must not retain lo/hi/val past fn.
func (t *rangeTable[T]) iterate(fn func(lo, hi [16]byte, v T) bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for i := 0; i < t.count_; i++ {
		o := idxHeaderLen + i*t.recSize
		var lo, hi [16]byte
		copy(lo[:], t.idx[o:o+16])
		copy(hi[:], t.idx[o+16:o+32])
		if !fn(lo, hi, t.codec.decode(t.idx[o+32:o+t.recSize], t.strs)) {
			return
		}
	}
}

func (t *rangeTable[T]) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	munmap(t.idx)
	munmap(t.strs)
	t.idx, t.strs, t.count_ = nil, nil, 0
}

// load compiles csvPath into a binary index (if missing or stale) and mmaps it.
func (t *rangeTable[T]) load(csvPath string, parse func(rec []string) (string, string, T, bool)) error {
	idxPath := swapExt(csvPath, ".idx")
	strsPath := swapExt(csvPath, ".strings")
	if needBuild(csvPath, idxPath) {
		if err := buildIndex(csvPath, idxPath, strsPath, parse, t.codec); err != nil {
			return err
		}
	}
	return t.open(idxPath, strsPath)
}

func (t *rangeTable[T]) open(idxPath, strsPath string) error {
	idx, err := mmapFile(idxPath)
	if err != nil {
		return err
	}
	if len(idx) < idxHeaderLen || string(idx[0:4]) != idxMagic {
		munmap(idx)
		return fmt.Errorf("bad index header in %s", idxPath)
	}
	recSize := int(binary.LittleEndian.Uint16(idx[6:8]))
	count := int(binary.LittleEndian.Uint32(idx[8:12]))
	if recSize != 32+t.codec.valSize {
		munmap(idx)
		return fmt.Errorf("index recSize %d != expected %d", recSize, 32+t.codec.valSize)
	}
	strs, err := mmapFile(strsPath)
	if err != nil {
		munmap(idx)
		return err
	}
	t.mu.Lock()
	oldIdx, oldStrs := t.idx, t.strs
	t.idx, t.strs, t.count_, t.recSize = idx, strs, count, recSize
	setFinalizer := !t.finalizerSet
	t.finalizerSet = true
	t.mu.Unlock()

	// Reload of the same table object: free the previous mapping now (safe — the
	// write lock we just held guarantees no reader was mid-lookup). Each fresh
	// table gets exactly one finalizer, which frees its final mapping when GC'd.
	munmap(oldIdx)
	munmap(oldStrs)
	if setFinalizer {
		runtime.SetFinalizer(t, (*rangeTable[T]).close)
	}
	return nil
}

// buildIndex parses csvPath and writes a sorted .idx + .strings pair atomically.
func buildIndex[T any](csvPath, idxPath, strsPath string, parse func(rec []string) (string, string, T, bool), c codec[T]) error {
	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	recSize := 32 + c.valSize
	pool := newStrPool()
	var flat []byte
	var lo, hi big.Int

	r := csv.NewReader(bufio.NewReaderSize(f, 1<<16))
	r.ReuseRecord = true
	r.FieldsPerRecord = -1
	for len(flat)/recSize < maxRangeRows {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		loStr, hiStr, val, ok := parse(rec)
		if !ok {
			continue
		}
		if _, ok := lo.SetString(loStr, 10); !ok {
			continue
		}
		if _, ok := hi.SetString(hiStr, 10); !ok {
			continue
		}
		if lo.Sign() < 0 || hi.Sign() < 0 || lo.BitLen() > 128 || hi.BitLen() > 128 {
			continue
		}
		start := len(flat)
		flat = append(flat, make([]byte, recSize)...)
		lo.FillBytes(flat[start : start+16])
		hi.FillBytes(flat[start+16 : start+32])
		c.encode(flat[start+32:start+recSize], val, pool)
	}

	n := len(flat) / recSize
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		oa, ob := order[a]*recSize, order[b]*recSize
		return bytes.Compare(flat[oa:oa+16], flat[ob:ob+16]) < 0
	})

	// write .idx (header + records in sorted order) to a temp, then rename.
	if err := writeFileAtomic(idxPath, func(w *bufio.Writer) error {
		var hdr [idxHeaderLen]byte
		copy(hdr[0:4], idxMagic)
		binary.LittleEndian.PutUint16(hdr[4:6], idxVersion)
		binary.LittleEndian.PutUint16(hdr[6:8], uint16(recSize))
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(n))
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		for _, idx := range order {
			o := idx * recSize
			if _, err := w.Write(flat[o : o+recSize]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return writeFileAtomic(strsPath, func(w *bufio.Writer) error {
		_, err := w.Write(pool.buf)
		return err
	})
}

// --- string pool ---

type strPool struct {
	buf []byte
	m   map[string]uint32
}

func newStrPool() *strPool { return &strPool{m: make(map[string]uint32, 4096)} }

func (p *strPool) add(s string) uint32 {
	if s == "" {
		return noStrOff
	}
	if off, ok := p.m[s]; ok {
		return off
	}
	if len(s) > 65535 {
		s = s[:65535]
	}
	off := uint32(len(p.buf))
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(s)))
	p.buf = append(p.buf, l[:]...)
	p.buf = append(p.buf, s...)
	p.m[s] = off
	return off
}

func readStr(strs []byte, off uint32) string {
	if off == noStrOff || int(off)+2 > len(strs) {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(strs[off : off+2]))
	start, end := int(off)+2, int(off)+2+n
	if end > len(strs) {
		return ""
	}
	return string(strs[start:end])
}

// --- codecs ---

var asnCodec = codec[asnVal]{
	valSize: 8,
	encode: func(dst []byte, v asnVal, p *strPool) {
		binary.LittleEndian.PutUint32(dst[0:4], v.asn)
		binary.LittleEndian.PutUint32(dst[4:8], p.add(v.name))
	},
	decode: func(val, strs []byte) asnVal {
		return asnVal{asn: binary.LittleEndian.Uint32(val[0:4]), name: readStr(strs, binary.LittleEndian.Uint32(val[4:8]))}
	},
}

var proxyCodec = codec[proxyVal]{
	valSize: 14,
	encode: func(dst []byte, v proxyVal, p *strPool) {
		binary.LittleEndian.PutUint32(dst[0:4], p.add(v.ptype))
		binary.LittleEndian.PutUint32(dst[4:8], p.add(v.usage))
		binary.LittleEndian.PutUint32(dst[8:12], p.add(v.threat))
		dst[12] = v.fraud
		if v.hasFraud {
			dst[13] = 1
		}
	},
	decode: func(val, strs []byte) proxyVal {
		return proxyVal{
			ptype:    readStr(strs, binary.LittleEndian.Uint32(val[0:4])),
			usage:    readStr(strs, binary.LittleEndian.Uint32(val[4:8])),
			threat:   readStr(strs, binary.LittleEndian.Uint32(val[8:12])),
			fraud:    val[12],
			hasFraud: val[13] != 0,
		}
	},
}

// --- CSV row parsers (unchanged) ---

func parseASNRow(intern func(string) string) func([]string) (string, string, asnVal, bool) {
	return func(rec []string) (string, string, asnVal, bool) {
		if len(rec) < 5 {
			return "", "", asnVal{}, false
		}
		asn, _ := strconv.ParseUint(strings.TrimSpace(rec[3]), 10, 32)
		name := strings.TrimSpace(rec[4])
		if asn == 0 && (name == "" || name == "-") {
			return "", "", asnVal{}, false
		}
		return rec[0], rec[1], asnVal{asn: uint32(asn), name: intern(name)}, true
	}
}

func parseProxyRow(intern func(string) string, cols proxyColumns) func([]string) (string, string, proxyVal, bool) {
	get := func(rec []string, idx int) string {
		if idx > 2 && idx < len(rec) {
			if s := strings.TrimSpace(rec[idx]); s != "" && s != "-" {
				return s
			}
		}
		return ""
	}
	return func(rec []string) (string, string, proxyVal, bool) {
		if len(rec) < 3 {
			return "", "", proxyVal{}, false
		}
		pt := strings.TrimSpace(rec[2])
		if pt == "" || pt == "-" {
			return "", "", proxyVal{}, false
		}
		v := proxyVal{ptype: intern(pt)}
		if s := get(rec, cols.usageType); s != "" {
			v.usage = intern(s)
		}
		if s := get(rec, cols.threat); s != "" {
			v.threat = intern(s)
		}
		if s := get(rec, cols.fraud); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 100 {
				v.fraud = uint8(n)
				v.hasFraud = true
			}
		}
		return rec[0], rec[1], v, true
	}
}

// interner keeps the CSV-parse signature stable; the string pool does the real dedup.
func newInterner() func(string) string {
	m := make(map[string]string, 4096)
	return func(s string) string {
		if v, ok := m[s]; ok {
			return v
		}
		m[s] = s
		return s
	}
}

// --- small helpers ---

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// needBuild reports whether the binary index must be (re)built: missing, or the CSV
// is newer than the index.
func needBuild(csvPath, idxPath string) bool {
	ci, err := os.Stat(csvPath)
	if err != nil {
		return false // no CSV → nothing to build (caller checks fileExists first)
	}
	ii, err := os.Stat(idxPath)
	if err != nil {
		return true
	}
	return ci.ModTime().After(ii.ModTime())
}

func swapExt(path, newExt string) string {
	return strings.TrimSuffix(path, filepath.Ext(path)) + newExt
}

func mmapFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := int(fi.Size())
	if size == 0 {
		return []byte{}, nil
	}
	return syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
}

func munmap(b []byte) {
	if len(b) > 0 {
		_ = syscall.Munmap(b)
	}
}

func writeFileAtomic(path string, write func(w *bufio.Writer) error) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	if err := write(w); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
