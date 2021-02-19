package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/encrypt"
)

func init() {
	v := mapInfo{
		Name:       "bandswitch",
		MathPrefix: "cilium_throttle",
		Handler: func(path string) {
			Parse(path, &mapType.EncryptKey{}, &mapType.EncryptValue{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.EncryptKey)
				v := value.(*mapType.EncryptValue)

				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
