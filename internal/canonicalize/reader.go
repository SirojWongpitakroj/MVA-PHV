package canonicalize

import (
	"bufio"
	"fmt"
	"os"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

type DatasetReader struct {
	Reader  *bufio.Scanner
	CurrLog *domain.Log
	file    *os.File
}

func NewDatasetReader() (*DatasetReader, error) {
	file, err := os.Open("../../../dataset/combined/openstack_uniform_combined.jsonl")
	if err != nil {
		return nil, fmt.Errorf("error opening a log source")
	}

	scanner := DatasetReader{CurrLog: &domain.Log{}}
	scanner.file = file
	scanner.Reader = bufio.NewScanner(file)

	return &scanner, nil
}

func (r *DatasetReader) Next() bool {
	if r.Reader.Scan() {
		logBytes := r.Reader.Bytes()

		r.parse(logBytes)

		//add logID, attr to AD
		var err error
		r.CurrLog.AD, err = domain.Ser(
			uint8(1), // format/version
			r.CurrLog.LogID,
			r.CurrLog.RegionID,
			r.CurrLog.SiteID,
			r.CurrLog.DevID,
			r.CurrLog.Type,
			r.CurrLog.TS,
		)

		if err != nil {
			panic(err)
		}

		r.encrypt(logBytes)
	} else {
		r.file.Close()
		if err := r.Reader.Err(); err != nil {
			panic(err)
		}
		return false
	}
	return true
}

func (r *DatasetReader) Record() *domain.Log {
	return r.CurrLog
}
