package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/lbmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "lb4_reverse_nat",
			MathPrefix: "cilium_lb4_reverse_nat",
			Handler: func(path string) {
				Parse(path, &mapType.RevNat4Key{}, &mapType.RevNat4Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.RevNat4Key)
					v := value.(*mapType.RevNat4Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb4_backends",
			MathPrefix: "cilium_lb4_backends",
			Handler: func(path string) {
				Parse(path, &mapType.Backend4Key{}, &mapType.Backend4Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Backend4Key)
					v := value.(*mapType.Backend4Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb4_services_v2",
			MathPrefix: "cilium_lb4_services_v2",
			Handler: func(path string) {
				Parse(path, &mapType.Service4Key{}, &mapType.Service4Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Service4Key)
					v := value.(*mapType.Service4Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb4_reverse_sk",
			MathPrefix: "cilium_lb4_reverse_sk",
			Handler: func(path string) {
				Parse(path, &mapType.SockRevNat4Key{}, &mapType.SockRevNat4Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.SockRevNat4Key)
					v := value.(*mapType.SockRevNat4Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
