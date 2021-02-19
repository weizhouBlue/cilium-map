package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/eventsmap"
)

func init() {
	v := mapInfo{
		Name:       "event",
		MathPrefix: "cilium_events",
		Handler: func(path string) {
			Parse(path, &mapType.Key{}, &mapType.Value{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.Key)
				v := value.(*mapType.Value)
				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
