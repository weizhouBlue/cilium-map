package mapPrint

import (
	"fmt"
	"os"
	"github.com/cilium/cilium/pkg/bpf"
    mapMetrics "github.com/cilium/cilium/pkg/maps/metricsmap"
)


func ParseMetric( path string  ){

	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

    m.MapKey=&mapMetrics.Key{}
    m.MapValue=&mapMetrics.Value{}
    m.DumpParser = bpf.ConvertKeyValue

	parse := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*mapMetrics.Key)
		v := value.(*mapMetrics.Value)
        fmt.Printf("key:%+v \n", *k)
        fmt.Printf("value:%+v\n",*v)
	}

	err = m.DumpWithCallbackIfExists(parse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map %s: %s\n", path, err)
		os.Exit(1)
	}

}
