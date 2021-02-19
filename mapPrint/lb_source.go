package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/lbmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "lb4_source_range",
			MathPrefix: "cilium_lb4_source_range",
			Handler: func(path string) {
				Parse(path, &mapType.SourceRangeKey4{}, &mapType.SourceRangeValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.SourceRangeKey4)
					v := value.(*mapType.SourceRangeValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_source_range",
			MathPrefix: "cilium_lb6_source_range",
			Handler: func(path string) {
				Parse(path, &mapType.SourceRangeKey6{}, &mapType.SourceRangeValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.SourceRangeKey6)
					v := value.(*mapType.SourceRangeValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
