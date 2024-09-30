package pingpong

import (
	"io/fs"
	"os"
)

//file system created to manage many resources manually
type filesystem struct {
	Filesystem fs.FS
}

//create new new file system for server
func createFilesystem() filesystem {
	return filesystem{
		Filesystem: newDefaultFS(),
	}
}

func newDefaultFS() *defaultFS {
	dir, _ := os.Getwd()
	return &defaultFS{
		prefix: dir,
		fs:     nil,
	}
}

type defaultFS struct {
	fs     fs.FS
	prefix string
}

// implement fs.FS interfance method
func (fs defaultFS) Open(name string) (fs.File, error) {
	if fs.fs == nil {
		return os.Open(name)
	}
	return fs.fs.Open(name)
}
