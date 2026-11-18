package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		if err := runInfo(nil); err != nil {
			fmt.Fprintln(os.Stderr, "noobtunnel:", err)
			os.Exit(1)
		}
		return
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "agent":
		err = runAgent(args)
	case "quick":
		err = runQuick(args)
	case "status":
		err = runStatus(args)
	case "info":
		err = runInfo(args)
	case "loopback-only":
		err = runLoopbackOnly(args)
	case "doctor":
		err = runDoctor(args)
	case "keygen":
		err = runKeygen(args)
	case "install":
		err = runInstall(args)
	case "version", "--version", "-v":
		printVersion()
	case "help", "--help", "-h":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "noobtunnel:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: noobtunnel <command> [flags]

  agent    Connect this machine to a control node
  quick    Find or install an agent and publish a resource
  status   Show local agent state
  info     Show version, agent state and settings (also the default)
  loopback-only [on|off|status]  Manage the local forwarding restriction
  doctor   Check local agent requirements
  keygen   Generate a WireGuard key pair
  install  Print an agent install command
  version  Show build information

Use noobtunnel <command> --help for options.
`)
}

func printVersion() {
	fmt.Printf("noobtunnel %s\ncommit     %s\nbuilt      %s\ngo         %s\nplatform   %s/%s\n",
		versionString(), commitString(), buildDateString(), goVersion(), goos(), goarch())
}
