package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	"os"
)

type mapInfo struct {
	Name       string
	MathPrefix string
	Handler    func(string)
}

var GlobalInfo = []mapInfo{}

func Parse(path string, key bpf.MapKey, value bpf.MapValue, parse func(key bpf.MapKey, value bpf.MapValue)) {
	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

	m.MapKey = key
	m.MapValue = value
	m.DumpParser = bpf.ConvertKeyValue
	err = m.DumpWithCallbackIfExists(parse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map %s: %s\n", path, err)
		os.Exit(1)
	}
}
