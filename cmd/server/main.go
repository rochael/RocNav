package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rochael/RocNav/internal/app"
	"github.com/rochael/RocNav/internal/config"
	"github.com/rochael/RocNav/internal/version"
)

func main() {
	addr := flag.String("addr", "", "HTTP listen address (default :8080)")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(help, "h", false, "Show help")
	showVersion := flag.Bool("version", false, "Show version")
	flag.BoolVar(showVersion, "v", false, "Show version")
	flag.Parse()

	if *help {
		fmt.Fprintf(os.Stdout, "Usage: %s [options]\n\nOptions:\n  --addr string   HTTP listen address (default :8080)\n  -h, --help      Show help\n  -v, --version   Show version\n", os.Args[0])
		os.Exit(0)
	}

	if *showVersion {
		fmt.Println(version.Version())
		os.Exit(0)
	}

	cfg := config.Load()
	if *addr != "" {
		cfg.Addr = *addr
	}

	a := app.NewWithConfig(cfg)
	a.Run()
}
