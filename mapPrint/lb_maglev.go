package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/lbmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "lb4_maglev",
			MathPrefix: "cilium_lb4_maglev",
			Handler: func(path string) {
				Parse(path, &mapType.MaglevOuterKey{}, &mapType.MaglevOuterVal{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.MaglevOuterKey)
					v := value.(*mapType.MaglevOuterVal)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_maglev",
			MathPrefix: "cilium_lb6_maglev",
			Handler: func(path string) {
				Parse(path, &mapType.MaglevOuterKey{}, &mapType.MaglevOuterVal{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.MaglevOuterKey)
					v := value.(*mapType.MaglevOuterVal)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb4_maglev_inner",
			MathPrefix: "cilium_lb4_maglev_inner",
			Handler: func(path string) {
				Parse(path, &mapType.MaglevInnerKey{}, &mapType.MaglevInnerVal{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.MaglevInnerKey)
					v := value.(*mapType.MaglevInnerVal)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_maglev_inner",
			MathPrefix: "cilium_lb6_maglev_inner",
			Handler: func(path string) {
				Parse(path, &mapType.MaglevInnerKey{}, &mapType.MaglevInnerVal{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.MaglevInnerKey)
					v := value.(*mapType.MaglevInnerVal)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
