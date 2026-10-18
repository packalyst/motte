package helper

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// DefaultRouteInterface returns the NIC that carries the default IPv4 route — the WAN /
// internet-facing interface. It parses `ip -4 route show default` and returns the `dev` of the
// first default route. Shared by the firewall and DHCP packages so this detection lives in one
// place. Returns an error if the command fails or there is no default route.
func DefaultRouteInterface() (string, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "dev" {
				return f[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("no default route found")
}
