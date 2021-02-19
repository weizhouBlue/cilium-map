package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/fragmap"
)

func init() {
	v := mapInfo{
		Name:       "frag",
		MathPrefix: "cilium_ipv4_frag_datagrams",
		Handler: func(path string) {
			Parse(path, &mapType.FragmentKey{}, &mapType.FragmentValue{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.FragmentKey)
				v := value.(*mapType.FragmentValue)
				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
