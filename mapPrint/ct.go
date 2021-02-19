package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/ctmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "ct4",
			MathPrefix: "cilium_ct4_",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey4{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey4)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct6",
			MathPrefix: "cilium_ct6_",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey6{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey6)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct4_gloabl",
			MathPrefix: "cilium_ct4_global",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey4Global{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey4Global)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct6_gloabl",
			MathPrefix: "cilium_ct6_global",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey6Global{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey6Global)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct4",
			MathPrefix: "cilium_ct_any4_",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey4{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey4)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct6",
			MathPrefix: "cilium_ct_any6_",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey6{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey6)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct4_global",
			MathPrefix: "cilium_ct_any4_global",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey4Global{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey4Global)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "ct6_global",
			MathPrefix: "cilium_ct_any6_global",
			Handler: func(path string) {
				Parse(path, &mapType.CtKey6Global{}, &mapType.CtEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CtKey6Global)
					v := value.(*mapType.CtEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
