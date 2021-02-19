package mapPrint

import (
	"fmt"
	"github.com/cilium/cilium/pkg/bpf"
	mapType "github.com/cilium/cilium/pkg/maps/policymap"
)

func init() {
	v := []mapInfo{
		mapInfo{
			Name:       "call_policy",
			MathPrefix: "cilium_call_policy",
			Handler: func(path string) {
				Parse(path, &mapType.CallKey{}, &mapType.CallValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.CallKey)
					v := value.(*mapType.CallValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "policy",
			MathPrefix: "cilium_policy_",
			Handler: func(path string) {
				Parse(path, &mapType.PolicyKey{}, &mapType.PolicyEntry{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.PolicyKey)
					v := value.(*mapType.PolicyEntry)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
		mapInfo{
			Name:       "call",
			MathPrefix: "cilium_calls_",
			Handler: func(path string) {
				Parse(path, &mapType.PlumbingKey{}, &mapType.PlumbingValue{}, func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(*mapType.PlumbingKey)
					v := value.(*mapType.PlumbingValue)

					fmt.Printf("key: %+v \n", *k)
					fmt.Printf("value: %+v\n", *v)
					fmt.Printf("\n")
				})
			},
		},
	}

	GlobalInfo = append(GlobalInfo, v...)

}
