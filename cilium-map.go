package main

import (
	"bpf-map/mapPrint"
	"fmt"
	"github.com/urfave/cli"
	"os"
	"path/filepath"
	"strings"
)

var BinName = os.Args[0]

func Usage() string {
	a := ""
	for _, v := range mapPrint.GlobalInfo {
		a += v.Name + "|"
	}
	a = strings.TrimRight(a, "|")
	return fmt.Sprintf(" %s dump PATH [%s]", BinName, a)
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
			Usage:     Usage(),
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
	if len(mapPath) == 0 {
		fmt.Fprintf(os.Stderr, "error, miss cilium-map path \n")
		fmt.Printf("%s\n", Usage())
		os.Exit(1)
	}

	ciliumMapType := ctx.Args().Get(1)
	if len(ciliumMapType) == 0 {
		lastLen := 0
		for _, v := range mapPrint.GlobalInfo {
			if len(v.MathPrefix) > 0 && strings.Contains(filepath.Base(mapPath), v.MathPrefix) {
				if len(v.MathPrefix) > lastLen {
					lastLen = len(v.MathPrefix)
					ciliumMapType = v.Name
				}
			}
		}

		if len(ciliumMapType) > 0 {
			fmt.Fprintf(os.Stderr, "set type to %v \n", ciliumMapType)
			goto OUT
		}
		fmt.Fprintf(os.Stderr, "error, miss cilium-map type \n")
		fmt.Printf("%s\n", Usage())
		os.Exit(1)
	}
OUT:
	for _, v := range mapPrint.GlobalInfo {
		if v.Name == ciliumMapType {
			v.Handler(mapPath)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "error, error cilium-map type \n")
	fmt.Printf("%s\n", Usage())
	os.Exit(1)
}
