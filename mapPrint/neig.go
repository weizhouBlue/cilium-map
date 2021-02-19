package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/neighborsmap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "nodeport_neigh4",
			MathPrefix: "cilium_nodeport_neigh4",
			Handler: func(path string) {
				Parse(path, &mapType.Key4{}, &mapType.Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Key4)
					v := value.(*mapType.Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "nodeport_neigh6",
			MathPrefix: "cilium_nodeport_neigh6",
			Handler: func(path string) {
				Parse(path, &mapType.Key6{}, &mapType.Value{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.Key6)
					v := value.(*mapType.Value)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
