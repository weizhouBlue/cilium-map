package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/eppolicymap"
)

func init() {
	v := mapInfo{
		Name:       "eppolicy",
		MathPrefix: "cilium_ep_to_policy",
		Handler: func(path string) {
			Parse(path, &mapType.EndpointKey{}, &mapType.EPPolicyValue{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.EndpointKey)
				v := value.(*mapType.EPPolicyValue)
				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
