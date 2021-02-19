package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/nat"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "snat_v4_external",
			MathPrefix: "cilium_snat_v4_external",
			Handler: func(path string) {
				Parse(path, &mapType.NatKey4{}, &mapType.NatEntry4{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.NatKey4)
					v := value.(*mapType.NatEntry4)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "snat_v6_external",
			MathPrefix: "cilium_snat_v6_external",
			Handler: func(path string) {
				Parse(path, &mapType.NatKey6{}, &mapType.NatEntry6{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.NatKey6)
					v := value.(*mapType.NatEntry6)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
