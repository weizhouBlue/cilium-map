package main

import (
	"fmt"
	"os"
	"github.com/urfave/cli"
	"bpf-map/mapPrint"
	"strings"
        "path/filepath"
)

type mapInfo struct {
	name string
        mathPrefix string
	handler func(string)
}

var GloablInfo = []mapInfo {
	mapInfo{ 
		name:"metrics" ,
                mathPrefix: "cilium_metrics",
		handler: mapPrint.ParseMetric ,
	} ,
        mapInfo{
                name:"bandswitch" ,
                mathPrefix: "cilium_throttle",
                handler: mapPrint.ParseBandswitch ,
        } ,
        mapInfo{
                name:"ct4" ,
                mathPrefix: "cilium_ct4_",
                handler: mapPrint.ParseCt4 ,
        } ,
        mapInfo{
                name:"ct6" ,
                mathPrefix: "cilium_ct6_",
                handler: mapPrint.ParseCt6 ,
        } ,
        mapInfo{
                name:"ct4_gloabl" ,
                mathPrefix: "cilium_ct4_global",
                handler: mapPrint.ParseCt4Global ,
        } ,
        mapInfo{
                name:"ct6_gloabl" ,
                mathPrefix: "cilium_ct6_global",
                handler: mapPrint.ParseCt6Global ,
        } ,
        mapInfo{
                name:"ct4" ,
                mathPrefix: "cilium_ct_any4_",
                handler: mapPrint.ParseCt4 ,
        } ,
        mapInfo{
                name:"ct6" ,
                mathPrefix: "cilium_ct_any6_",
                handler: mapPrint.ParseCt6 ,
        } ,
        mapInfo{
                name:"ct4_global" ,
                mathPrefix: "cilium_ct_any4_global",
                handler: mapPrint.ParseCt4Global ,
        } ,
        mapInfo{
                name:"ct6_global" ,
                mathPrefix: "cilium_ct_any6_global",
                handler: mapPrint.ParseCt6Global ,
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
               lastLen:=0
               for _,v:=range GloablInfo {
                   if len(v.mathPrefix)>0 && strings.Contains( filepath.Base(mapPath) , v.mathPrefix) {
                        if len(v.mathPrefix)>lastLen {
                           lastLen=len(v.mathPrefix)
                           ciliumMapType=v.name
                        }
                   }
                }

                if len(ciliumMapType)>0 {
                        fmt.Fprintf(os.Stderr,"set type to %v \n", ciliumMapType)
                        goto OUT
                }
		fmt.Fprintf(os.Stderr, "error, miss cilium-map type \n", )
		fmt.Printf("%s\n", Usage() )
		os.Exit(1)
	}
OUT:
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
