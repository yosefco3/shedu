package watch

import (
	"bytes"
	"context"
	"io"
	"os"
	"syscall"
	"time"
)

// TailLines streams complete lines appended to path, starting at its current
// end. It reopens the file when it is rotated (new inode) or truncated.
func TailLines(ctx context.Context, path string, poll time.Duration) (<-chan string, error) {
	if poll <= 0 {
		poll = time.Second
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, err
	}
	out := make(chan string, 256)
	go func() {
		defer close(out)
		defer func() { f.Close() }()
		var partial []byte
		buf := make([]byte, 64*1024)
		ino := inodeOf(f)
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			for {
				n, rerr := f.Read(buf)
				if n > 0 {
					offset += int64(n)
					partial = append(partial, buf[:n]...)
					for {
						i := bytes.IndexByte(partial, '\n')
						if i < 0 {
							break
						}
						line := string(partial[:i])
						partial = partial[i+1:]
						select {
						case out <- line:
						case <-ctx.Done():
							return
						}
					}
				}
				if rerr != nil || n == 0 {
					break
				}
			}
			// rotation / truncation check
			if st, err := os.Stat(path); err == nil {
				rotated := inodeOfInfo(st) != ino
				if rotated || st.Size() < offset {
					nf, err := os.Open(path)
					if err == nil {
						f.Close()
						f, offset, ino, partial = nf, 0, inodeOf(nf), nil
						continue // drain the new file immediately
					}
				}
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func inodeOf(f *os.File) uint64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return inodeOfInfo(st)
}

func inodeOfInfo(st os.FileInfo) uint64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}
