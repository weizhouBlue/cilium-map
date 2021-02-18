package mapPrint

import (
	"fmt"
	"os"
	"github.com/cilium/cilium/pkg/bpf"
        mapType "github.com/cilium/cilium/pkg/maps/bwmap"
)


func ParseBandswitch( path string  ){

	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

        m.MapKey=&mapType.EdtId{}
        m.MapValue=&mapType.EdtInfo{}
        m.DumpParser = bpf.ConvertKeyValue

	parse := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*mapType.EdtId)
		v := value.(*mapType.EdtInfo)
                fmt.Printf("key: %+v \n", *k)
                fmt.Printf("value: %+v\n",*v)
                fmt.Printf("\n")
	}

	err = m.DumpWithCallbackIfExists(parse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map %s: %s\n", path, err)
		os.Exit(1)
	}

}
