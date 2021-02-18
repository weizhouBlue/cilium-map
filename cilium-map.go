package main

import (
	"fmt"
	"os"
	"github.com/urfave/cli"
	"bpf-map/mapPrint"
	"strings"
)

type mapInfo struct {
	name string
	handler func(string)
}

var GloablInfo = []mapInfo {
	mapInfo{ 
		name:"metrics" ,
		handler: mapPrint.ParseMetric ,
	} ,
}

var BinName="cilium-map"

func Usage() string{
	a:=""
	for _ , v:=range GloablInfo {
		a+=v.name+"|"
	}
	a=strings.TrimRight(a , "|" )
	return fmt.Sprintf(" %s dump PATH [%s]",BinName, a)
}



func main() {
	app := cli.NewApp()
	app.Name = BinName
	app.Usage = "Generic tool to introspect BPF maps"
	app.UsageText = "cilium-map dump PATH  MAPTYPE "
	app.Version = "1.0"
	app.Commands = []cli.Command{
		{
			Name:      "dump",
			Aliases:   []string{"d"},
			Usage:     Usage() ,
			ArgsUsage: "<mapName>",
			Action:    dumpMap,
		},
	}

	app.Run(os.Args)
}


func dumpMap(ctx *cli.Context) {
	if len(ctx.Args()) < 1 {
		cli.ShowCommandHelp(ctx, "dump")
		os.Exit(1)
	}

	mapPath := ctx.Args().Get(0)
	if len(mapPath)==0 {
		fmt.Fprintf(os.Stderr, "error, miss cilium-map path \n", )
		fmt.Printf("%s\n", Usage() )
		os.Exit(1)
	}

	ciliumMapType := ctx.Args().Get(1)
	if len(ciliumMapType)==0 {
		fmt.Fprintf(os.Stderr, "error, miss cilium-map type \n", )
		fmt.Printf("%s\n", Usage() )
		os.Exit(1)
	}

	for _,v:=range GloablInfo {
		if v.name==ciliumMapType {
			v.handler(mapPath)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "error, error cilium-map type \n", )
	fmt.Printf("%s\n", Usage() )
	os.Exit(1)
}
