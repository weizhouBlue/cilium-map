package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/ipcache"
)

func init() {
	v := mapInfo{
		Name:       "ipcache",
		MathPrefix: "cilium_ipcache",
		Handler: func(path string) {
			Parse(path, &mapType.Key{}, &mapType.RemoteEndpointInfo{}, func(key bpf.MapKey, value bpf.MapValue) {
				k := key.(*mapType.Key)
				v := value.(*mapType.RemoteEndpointInfo)
				fmt.Printf("key: %+v \n", *k)
				fmt.Printf("value: %+v\n", *v)
				fmt.Printf("\n")
			})
		},
	}

	GlobalInfo = append(GlobalInfo, v)

}
