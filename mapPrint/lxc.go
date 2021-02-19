package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/lxcmap"
)

func init() {
	v := mapInfo{
		Name:       "lxc",
		MathPrefix: "cilium_lxc",
		Handler: func(path string) {
			Parse(path, &mapType.EndpointKey{}, &mapType.EndpointInfo{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.EndpointKey)
				v := value.(*mapType.EndpointInfo)

				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
