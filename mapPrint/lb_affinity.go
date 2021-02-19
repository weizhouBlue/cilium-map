package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/lbmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "lb_affinity_match",
			MathPrefix: "cilium_lb_affinity_match",
			Handler: func(path string) {
				Parse(path, &mapType.AffinityMatchKey{}, &mapType.AffinityMatchValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.AffinityMatchKey)
					v := value.(*mapType.AffinityMatchValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb4_affinity",
			MathPrefix: "cilium_lb4_affinity",
			Handler: func(path string) {
				Parse(path, &mapType.Affinity4Key{}, &mapType.AffinityValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Affinity4Key)
					v := value.(*mapType.AffinityValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "lb6_affinity",
			MathPrefix: "cilium_lb6_affinity",
			Handler: func(path string) {
				Parse(path, &mapType.Affinity6Key{}, &mapType.AffinityValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Affinity6Key)
					v := value.(*mapType.AffinityValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
