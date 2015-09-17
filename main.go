/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Justin Wong <justin.w.xd@gmail.com>
 *
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/xvtom/gohop/hop"
)

var srvMode, cltMode, debug, getVersion bool
var cfgFile string

var VERSION = "0.3.3-dev"

func main() {
	flag.BoolVar(&getVersion, "version", false, "Get Version info")
	flag.BoolVar(&debug, "debug", false, "Provide debug info")
	flag.StringVar(&cfgFile, "config", "", "configfile")
	flag.Parse()

	if getVersion {
		fmt.Println("GoHop: Yet Another VPN to Escape from Censorship")
		fmt.Printf("Version: %s\n", VERSION)
		os.Exit(0)
	}

	checkerr := func(err error) {
		if err != nil {
			log.Print(err.Error())
			log.Fatal(err.Error())
		}
	}

	if cfgFile == "" {
		cfgFile = flag.Arg(0)
	}

	log.Printf("using config file: %v", cfgFile)
	fmt.Println(cfgFile)

	icfg, err := hop.ParseHopConfig(cfgFile)
	// //log.Debug("%v", icfg)
	checkerr(err)

	maxProcs := runtime.GOMAXPROCS(0)
	if maxProcs < 2 {
		runtime.GOMAXPROCS(2)
	}

	switch cfg := icfg.(type) {
	case hop.HopServerConfig:
		err := hop.NewServer(cfg)
		checkerr(err)
	case hop.HopClientConfig:
		err := hop.NewClient(cfg)
		checkerr(err)
	default:
		log.Print("Invalid config file")
	}
}
