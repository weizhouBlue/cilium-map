//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"unsafe"
	
	"github.com/cilium/cilium/pkg/bpf"
        mapMetrics "github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/urfave/cli"
)


// Helper that parses and stores map keys/values
type byteValue struct {
	data []byte

	// Size of related values (so not necessarily the size of the data)
	size uint32
}

func newByteValue(s string, expected, sz uint32) (byteValue, error) {
	b, err := hex.DecodeString(s)
	if err == nil && uint32(len(b)) != expected {
		err = fmt.Errorf("Expected length %v, not %v", expected, len(b))
	}
	return byteValue{b, sz}, err
}

func (b byteValue) NewValue() bpf.MapValue {
	return byteValue{make([]byte, b.size), b.size}
}

func (b byteValue) GetKeyPtr() unsafe.Pointer {
	return b.GetValuePtr()
}

func (b byteValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&b.data[0])
}

func (b byteValue) DeepCopyMapValue() bpf.MapValue {
    n:=make([]byte,len(b.data) )
    copy(n,b.data)
    a:=byteValue{
       data: n,
       size: b.size ,
    }

    return a
}

func (b byteValue) DeepCopyMapKey() bpf.MapKey {
    n:=make([]byte,len(b.data) )
    copy(n,b.data)
    a:=byteValue{
       data: n,
       size: b.size ,
    }

    return a
}

func (b byteValue) String() string {
    return string(b.data)
}


func main() {
	app := cli.NewApp()
	app.Name = "bpf-map"
	app.Usage = "Generic tool to introspect BPF maps"
	app.UsageText = "bpf-map { dump | info | update | remove } <map file>"
	app.Version = "1.0"
	app.Commands = []cli.Command{
		{
			Name:      "dump",
			Aliases:   []string{"d"},
			Usage:     "Dump contents of map",
			ArgsUsage: "<map path>",
			Action:    dumpMap,
		},
		{
			Name:      "info",
			Aliases:   []string{"i"},
			Usage:     "Print metadata information of map",
			ArgsUsage: "<map path>",
			Action:    infoMap,
		},
		{
			Name:      "update",
			Aliases:   []string{"u"},
			Usage:     "Update a map entry with keys and values in hex",
			ArgsUsage: "<map path> <key> <value>",
			Action:    updateMap,
		},
		{
			Name:      "remove",
			Aliases:   []string{"r"},
			Usage:     "Remove a map entry (key in hex)",
			ArgsUsage: "<map path> <key>",
			Action:    deleteKey,
		},
	}

	app.Run(os.Args)
}

func dumpMap(ctx *cli.Context) {
	if len(ctx.Args()) < 1 {
		cli.ShowCommandHelp(ctx, "dump")
		os.Exit(1)
	}

	path := ctx.Args().Get(0)
	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

        m.MapKey=&mapMetrics.Key{}
        m.MapValue=&mapMetrics.Value{}
        m.DumpParser = bpf.ConvertKeyValue

	parse := func(key bpf.MapKey, value bpf.MapValue) {
	k := key.(*mapMetrics.Key)
	v := value.(*mapMetrics.Value)
        fmt.Printf("key:%+v \n", *k)
        fmt.Printf("value:%+v\n",*v)
	}

	err = m.DumpWithCallbackIfExists(parse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to dump map %s: %s\n", path, err)
		os.Exit(1)
	}
}

func infoMap(ctx *cli.Context) {
	if len(ctx.Args()) < 1 {
		cli.ShowCommandHelp(ctx, "info")
		os.Exit(1)
	}

	path := ctx.Args().Get(0)
	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

	fmt.Printf("Type:\t\t%s\nKey size:\t%d\nValue size:\t%d\nMax entries:\t%d\nFlags:\t\t%#x\n",
		m.MapType.String(), m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)

	fmt.Printf("Owner prog type:\t%s\n", m.OwnerProgType.String())
}

func updateMap(ctx *cli.Context) {
	if len(ctx.Args()) < 3 {
		cli.ShowCommandHelp(ctx, "update")
		os.Exit(1)
	}

	path := ctx.Args().Get(0)
	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

	key, err := newByteValue(ctx.Args().Get(1), m.KeySize, m.ValueSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid key: %s\n", err)
		os.Exit(1)
	}

	value, err := newByteValue(ctx.Args().Get(2), m.ValueSize, m.ValueSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid value: %s\n", err)
		os.Exit(1)
	}

	if err := m.Update(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to set key: %s\n", err)
		os.Exit(1)
	} else {
		fmt.Println("Updated")
	}
}

func deleteKey(ctx *cli.Context) {
	if len(ctx.Args()) < 2 {
		cli.ShowCommandHelp(ctx, "remove")
		os.Exit(1)
	}

	path := ctx.Args().Get(0)
	m, err := bpf.OpenMap(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open map %s: %s\n", path, err)
		os.Exit(1)
	}

	key, err := newByteValue(ctx.Args().Get(1), m.KeySize, m.ValueSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid key: %s\n", err)
		os.Exit(1)
	}

	if err := m.Delete(key); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to remove key: %s\n", err)
		os.Exit(1)
	} else {
		fmt.Println("Removed")
	}
}
