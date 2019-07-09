package archiver

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"log"
)

// Tar is for Tar format
var Tar tarFormat

var(
	defaultFilterFunc = func(path string)bool{
		return false
	}
)

func init() {
	RegisterFormat("Tar", Tar)
}

type tarFormat struct{}

func (tarFormat) Match(filename string) bool {
	return strings.HasSuffix(strings.ToLower(filename), ".tar") || isTar(filename)
}

const tarBlockSize int = 512

// isTar checks the file has the Tar format header by reading its beginning
// block.
func isTar(tarPath string) bool {
	f, err := os.Open(tarPath)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, tarBlockSize)
	if _, err = io.ReadFull(f, buf); err != nil {
		return false
	}

	return hasTarHeader(buf)
}

// hasTarHeader checks passed bytes has a valid tar header or not. buf must
// contain at least 512 bytes and if not, it always returns false.
func hasTarHeader(buf []byte) bool {
	if len(buf) < tarBlockSize {
		return false
	}

	b := buf[148:156]
	b = bytes.Trim(b, " \x00") // clean up all spaces and null bytes
	if len(b) == 0 {
		return false // unknown format
	}
	hdrSum, err := strconv.ParseUint(string(b), 8, 64)
	if err != nil {
		return false
	}

	// According to the go official archive/tar, Sun tar uses signed byte
	// values so this calcs both signed and unsigned
	var usum uint64
	var sum int64
	for i, c := range buf {
		if 148 <= i && i < 156 {
			c = ' ' // checksum field itself is counted as branks
		}
		usum += uint64(uint8(c))
		sum += int64(int8(c))
	}

	if hdrSum != usum && int64(hdrSum) != sum {
		return false // invalid checksum
	}

	return true
}

// Write outputs a .tar file to a Writer containing the
// contents of files listed in filePaths. File paths can
// be those of regular files or directories. Regular
// files are stored at the 'root' of the archive, and
// directories are recursively added.
func (tarFormat) Write(output io.Writer, filePaths []string) error {
	return writeTar("", filePaths, output, "", true, defaultFilterFunc)
}

func (tarFormat) Write2(output io.Writer, pathPrefix string, filePaths []string, recursive bool, filterFunc func(path string)bool) error {
	if filterFunc==nil{
		filterFunc = defaultFilterFunc
	}
	return writeTar(pathPrefix, filePaths, output, "", recursive, filterFunc)
}

// Make creates a .tar file at tarPath containing the
// contents of files listed in filePaths. File paths can
// be those of regular files or directories. Regular
// files are stored at the 'root' of the archive, and
// directories are recursively added.
func (tarFormat) Make(tarPath string, filePaths []string) error {
	out, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("error creating %s: %v", tarPath, err)
	}
	defer out.Close()

	return writeTar("", filePaths, out, tarPath, true, defaultFilterFunc)
}

func writeTar(pathPrefix string, filePaths []string, output io.Writer, dest string, recursive bool, filterFunc func(path string)bool) error {
	tarWriter := tar.NewWriter(output)
	defer tarWriter.Close()

	return tarball(pathPrefix, filePaths, tarWriter, dest, recursive, filterFunc)
}

// tarball writes all files listed in filePaths into tarWriter, which is
// writing into a file located at dest.
func tarball(pathPrefix string, filePaths []string, tarWriter *tar.Writer, dest string, recursive bool, filterFunc func(path string)bool) error {
	for _, fpath := range filePaths {
		err := tarFile(tarWriter, pathPrefix, fpath, dest, recursive, filterFunc)
		if err != nil {
			return err
		}
	}
	return nil
}

// tarFile writes the file at source into tarWriter. It does so
// recursively for directories.
func tarFile(tarWriter *tar.Writer, pathPrefix string, source, dest string, recursive bool, filterFunc func(path string)bool) error {

	//if len(pathPrefix)>0 && !strings.HasPrefix(source, pathPrefix){
		//return fmt.Errorf("%s doesnot has prefix of %s",source,pathPrefix)
		//return nil
	//}

	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("%s: stat: %v", source, err)
	}

	var baseDir string
	if sourceInfo.IsDir() {
		baseDir = filepath.Base(source)
	}
	if len(pathPrefix)>0 && strings.HasPrefix(source, pathPrefix){
		baseDir = filepath.Base(pathPrefix)
	}

	var gitConfigPath = filepath.Join(source,".git")
	source = filepath.Dir(gitConfigPath)

	addToTarFunc := func(source, fpath string, info os.FileInfo, err error) error{

		if err != nil {
			return fmt.Errorf("error walking to %s: %v", fpath, err)
		}

		// filter
		if strings.HasPrefix(fpath, gitConfigPath){
			return nil
		}
		if len(fpath)>len(source){
			pathToCheck := fpath[len(source)+1:]
			if info.IsDir(){
				pathToCheck = filepath.ToSlash(pathToCheck)
				if !strings.HasSuffix(pathToCheck, "/"){
					pathToCheck = pathToCheck + "/"
				}
			}
			if filterFunc(pathToCheck){
				return nil
			}
		}

		header, err := tar.FileInfoHeader(info, fpath)
		if err != nil {
			return fmt.Errorf("%s: making header: %v", fpath, err)
		}

		if baseDir != "" {
			header.Name = filepath.ToSlash(filepath.Join(baseDir, strings.TrimPrefix(fpath, source)))
		}

		if header.Name == dest {
			// our new tar file is inside the directory being archived; skip it
			return nil
		}

		if info.IsDir() {
			header.Name += "/"
		}

		//make mod time correct
		header.Format = tar.FormatPAX

		err = tarWriter.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("%s: writing header: %v", fpath, err)
		}

		if info.IsDir() {
			return nil
		}

		if header.Typeflag == tar.TypeReg {
			file, err := os.Open(fpath)
			if err != nil {
				err = fmt.Errorf("%s: open: %v", fpath, err)
				log.Printf("write err:%v",err)
				return err
			}
			defer file.Close()

			_, err = io.CopyN(tarWriter, file, info.Size())
			if err != nil && err != io.EOF {
				err = fmt.Errorf("%s: copying contents: %v", fpath, err)
				log.Printf("write err:%v",err)
				return err
			}
		}
		return nil
	}

	if recursive{
		return filepath.Walk(source, func(fpath string, info os.FileInfo, err error) error {
			return addToTarFunc(source, fpath, info, err)
		})
	}


	return addToTarFunc(pathPrefix, source, sourceInfo, nil)
}

// Read untars a .tar file read from a Reader and puts
// the contents into destination.
func (tarFormat) Read(input io.Reader, destination string) error {
	return untar(tar.NewReader(input), destination)
}

// Open untars source and puts the contents into destination.
func (tarFormat) Open(source, destination string) error {
	f, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("%s: failed to open archive: %v", source, err)
	}
	defer f.Close()

	return Tar.Read(f, destination)
}

// untar un-tarballs the contents of tr into destination.
func untar(tr *tar.Reader, destination string) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if err := untarFile(tr, header, destination); err != nil {
			return err
		}
	}
	return nil
}

// untarFile untars a single file from tr with header header into destination.
func untarFile(tr *tar.Reader, header *tar.Header, destination string) error {
	err := sanitizeExtractPath(header.Name, destination)
	if err != nil {
		return err
	}

	destpath := filepath.Join(destination, header.Name)

	switch header.Typeflag {
	case tar.TypeDir:
		return mkdir(destpath)
	case tar.TypeReg, tar.TypeRegA, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return writeNewFileWithFileInfo(destpath, tr, header.FileInfo().Mode(), header.FileInfo())
	case tar.TypeSymlink:
		return writeNewSymbolicLink(destpath, header.Linkname)
	case tar.TypeLink:
		return writeNewHardLink(destpath, filepath.Join(destination, header.Linkname))
	case tar.TypeXGlobalHeader:
		// ignore the pax global header from git generated tarballs
		return nil
	default:
		return fmt.Errorf("%s: unknown type flag: %c", header.Name, header.Typeflag)
	}
}
