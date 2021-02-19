package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/sockmap"
)

func init() {
	v := mapInfo{
		Name:       "sock_ops",
		MathPrefix: "cilium_sock_ops",
		Handler: func(path string) {
			Parse(path, &mapType.SockmapKey{}, &mapType.SockmapValue{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.SockmapKey)
				v := value.(*mapType.SockmapValue)

				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
