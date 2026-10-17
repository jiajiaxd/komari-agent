package loginmon

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"
)

// tailFile follows path from its current end, calling onLine for every new
// complete line. It reopens the file after rotation or truncation and returns
// when ctx is done.
func tailFile(ctx context.Context, path string, interval time.Duration, onLine func(string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var partial []byte
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		// Rotation: the path now points to a different file, or the file shrank.
		if pathInfo, err := os.Stat(path); err == nil {
			cur, curErr := f.Stat()
			rotated := curErr != nil || !os.SameFile(cur, pathInfo)
			truncated := !rotated && pathInfo.Size() < offset
			if rotated || truncated {
				if nf, err := os.Open(path); err == nil {
					if rotated {
						// Drain what was written to the old file before it was rotated.
						readLines(f, buf, partial, onLine)
					}
					f.Close()
					f = nf
					offset = 0
					partial = nil
				}
			}
		}

		partial = readLines(f, buf, partial, onLine)
		if pos, err := f.Seek(0, io.SeekCurrent); err == nil {
			offset = pos
		}
	}
}

func readLines(f *os.File, buf, partial []byte, onLine func(string)) []byte {
	for {
		n, err := f.Read(buf)
		if n > 0 {
			partial = append(partial, buf[:n]...)
			for {
				i := bytes.IndexByte(partial, '\n')
				if i < 0 {
					break
				}
				onLine(string(bytes.TrimRight(partial[:i], "\r")))
				partial = partial[i+1:]
			}
			if len(partial) > 64*1024 {
				partial = nil
			}
		}
		if err != nil || n == 0 {
			return partial
		}
	}
}
