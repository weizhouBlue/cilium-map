package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/ipmasq"
)

func init() {
	v := mapInfo{
		Name:       "ipmasq",
		MathPrefix: "cilium_ipmasq_v4",
		Handler: func(path string) {
			Parse(path, &mapType.Key4{}, &mapType.Value{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.Key4)
				v := value.(*mapType.Value)
				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
