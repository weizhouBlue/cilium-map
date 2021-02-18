package mapPrint

import (
	"fmt"
	"os"
	"github.com/cilium/cilium/pkg/bpf"
        mapType "github.com/cilium/cilium/pkg/maps/ctmap"
)


func ParseCt4( path string  ){
	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

        m.MapKey=&mapType.CtKey4{}
        m.MapValue=&mapType.CtEntry{}
        m.DumpParser = bpf.ConvertKeyValue
	parse := func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*mapType.CtKey4)
		v := value.(*mapType.CtEntry)
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



func ParseCt6( path string  ){
        m, err := bpf.OpenMap(path)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
                os.Exit(1)
        }

        m.MapKey=&mapType.CtKey6{}
        m.MapValue=&mapType.CtEntry{}
        m.DumpParser = bpf.ConvertKeyValue
        parse := func(key bpf.MapKey, value bpf.MapValue) {
                k := key.(*mapType.CtKey6)
                v := value.(*mapType.CtEntry)
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


func ParseCt4Global( path string  ){
        m, err := bpf.OpenMap(path)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
                os.Exit(1)
        }

        m.MapKey=&mapType.CtKey4Global{}
        m.MapValue=&mapType.CtEntry{}
        m.DumpParser = bpf.ConvertKeyValue
        parse := func(key bpf.MapKey, value bpf.MapValue) {
                k := key.(*mapType.CtKey4Global)
                v := value.(*mapType.CtEntry)
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

func ParseCt6Global( path string  ){
        m, err := bpf.OpenMap(path)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
                os.Exit(1)
        }

        m.MapKey=&mapType.CtKey6Global{}
        m.MapValue=&mapType.CtEntry{}
        m.DumpParser = bpf.ConvertKeyValue
        parse := func(key bpf.MapKey, value bpf.MapValue) {
                k := key.(*mapType.CtKey6Global)
                v := value.(*mapType.CtEntry)
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

