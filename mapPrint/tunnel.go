package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/tunnel"
)

func init() {
	v := mapInfo{
		Name:       "tunnel",
		MathPrefix: "cilium_tunnel_map",
		Handler: func(path string) {
			Parse(path, &mapType.TunnelEndpoint{}, &mapType.TunnelEndpoint{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.TunnelEndpoint)
				v := value.(*mapType.TunnelEndpoint)

				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
