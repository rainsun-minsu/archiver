package archiver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/nwaples/rardecode/v2"
)

func rarVints(values ...uint64) []byte {
	var out []byte
	for _, v := range values {
		out = binary.AppendUvarint(out, v)
	}
	return out
}

func rarBlock(header []byte) []byte {
	data := append(rarVints(uint64(len(header))), header...)
	return append(binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(data)), data...)
}

// Construct valid RAR5 headers so the dictionary guard is reached before any
// compressed data is decoded or the advertised dictionary is allocated.
func rarFixture(name string, contents []byte, oversized bool) []byte {
	out := []byte("Rar!\x1a\x07\x01\x00")
	out = append(out, rarBlock(rarVints(1, 0, 0))...)
	header := rarVints(2, 2, uint64(len(contents)))
	if oversized {
		// Unknown unpacked size and a 512 MiB dictionary: the decoder cannot
		// reduce the dictionary using the advertised unpacked size.
		header = append(header, rarVints(8, 0, 0644, (12<<10)|(1<<7), 1, uint64(len(name)))...)
	} else {
		header = append(header, rarVints(4, uint64(len(contents)), 0644)...)
		header = binary.LittleEndian.AppendUint32(header, crc32.ChecksumIEEE(contents))
		header = append(header, rarVints(0, 1, uint64(len(name)))...)
	}
	header = append(header, name...)
	out = append(out, rarBlock(header)...)
	out = append(out, contents...)
	return append(out, rarBlock(rarVints(5, 0, 0))...)
}

func TestRarStoredReadAndOpen(t *testing.T) {
	for _, method := range []string{"Read", "Open"} {
		t.Run(method, func(t *testing.T) {
			contents := []byte("SL archive compatibility\n")
			archive := rarFixture("nested/provider", contents, false)
			dest := t.TempDir()
			var err error
			if method == "Read" {
				err = Rar.Read(bytes.NewReader(archive), dest)
			} else {
				source := filepath.Join(t.TempDir(), "test.rar")
				if err = os.WriteFile(source, archive, 0600); err != nil {
					t.Fatal(err)
				}
				err = Rar.Open(source, dest)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dest, "nested/provider"))
			if err != nil || !bytes.Equal(got, contents) {
				t.Fatalf("extraction: %q, %v", got, err)
			}
		})
	}
}

func TestRarRejectsOversizedDictionaryBeforeExtraction(t *testing.T) {
	dest := t.TempDir()
	err := Rar.Read(bytes.NewReader(rarFixture("large", []byte{0}, true)), dest)
	if !errors.Is(err, rardecode.ErrDictionaryTooLarge) {
		t.Fatalf("expected dictionary limit, got %v", err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected extracted entries: %v, %v", entries, err)
	}
}

func TestRarCorruptDataRejected(t *testing.T) {
	if err := Rar.Read(bytes.NewReader([]byte("invalid archive")), t.TempDir()); err == nil {
		t.Fatal("accepted corrupt RAR")
	}
}

func TestRar5CompressedUpstreamFixture(t *testing.T) {
	dest := t.TempDir()
	if err := Rar.Open("testdata-rar/rar5-compressed.rar", dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "test.bin"))
	if err != nil || len(got) != 1200 {
		t.Fatalf("compressed extraction length=%d, error=%v", len(got), err)
	}
	// Expected contents from libarchive v3.8.2 verify_data(..., 0, 1200).
	for i := 0; i < len(got)/4; i++ {
		k := i + 1
		want := k*k - 3*k + 1
		if want < 0 {
			want = 0
		}
		if binary.LittleEndian.Uint32(got[4*i:4*i+4]) != uint32(want) {
			t.Fatalf("compressed fixture word %d differs", i)
		}
	}
}
