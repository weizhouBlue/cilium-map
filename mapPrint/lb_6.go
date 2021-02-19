package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/lbmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "lb6_reverse_nat",
			MathPrefix: "cilium_lb6_reverse_nat",
			Handler: func(path string) {
				Parse(path, &mapType.RevNat6Key{}, &mapType.RevNat6Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.RevNat6Key)
					v := value.(*mapType.RevNat6Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_backends",
			MathPrefix: "cilium_lb6_backends",
			Handler: func(path string) {
				Parse(path, &mapType.Backend6Key{}, &mapType.Backend6Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Backend6Key)
					v := value.(*mapType.Backend6Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_services_v2",
			MathPrefix: "cilium_lb6_services_v2",
			Handler: func(path string) {
				Parse(path, &mapType.Service6Key{}, &mapType.Service6Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Service6Key)
					v := value.(*mapType.Service6Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_reverse_sk",
			MathPrefix: "cilium_lb6_reverse_sk",
			Handler: func(path string) {
				Parse(path, &mapType.SockRevNat6Key{}, &mapType.SockRevNat6Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.SockRevNat6Key)
					v := value.(*mapType.SockRevNat6Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
