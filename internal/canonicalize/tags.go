package canonicalize

import (
	"regexp"
	"strings"
)

var (
	haiPrefix  = regexp.MustCompile(`^P([1-4])_(.+)$`)
	typePrefix = regexp.MustCompile(`^[A-Za-z]+`)
	swatTagRE  = regexp.MustCompile(`^([A-Za-z]+)([1-6])[0-9]{2,}$`)
)

func wadiTag(raw string) (processColumn, bool) {
	parts := strings.SplitN(raw, "_", 2)
	if len(parts) != 2 {
		return processColumn{}, false // Plant-wide derived columns have no site.
	}
	var site string
	switch strings.ToUpper(parts[0]) {
	case "1", "2", "3":
		site = "P" + parts[0]
	case "2A", "2B":
		site = "P" + strings.ToUpper(parts[0])
	default:
		return processColumn{}, false
	}
	last := strings.LastIndex(parts[1], "_")
	if last <= 0 || last == len(parts[1])-1 {
		return processColumn{}, false
	}
	device := parts[1][:last]
	measurement := parts[1][last+1:]
	family := strings.SplitN(device, "_", 2)[0]
	if family == "" || measurement == "" {
		return processColumn{}, false
	}
	return processColumn{site: site, device: device, typ: strings.ToUpper(family + "_" + measurement)}, true
}

func haiTag(raw string) (processColumn, bool) {
	match := haiPrefix.FindStringSubmatch(raw)
	if match == nil {
		return processColumn{}, false // x100* auxiliary channels have no P1-P4 site.
	}
	device := match[2]
	family := typePrefix.FindString(device)
	if family == "" {
		family = device
	}
	typ := strings.ToUpper(family)
	if split := strings.IndexByte(device, '_'); split > 0 {
		// An explicit attribute suffix, such as PIT01_HH, shares PIT01.
		typ += "_" + strings.ToUpper(device[split+1:])
		device = device[:split]
	} else if strings.HasSuffix(device, "SP") && len(device) > len(family)+2 &&
		device[len(device)-3] >= '0' && device[len(device)-3] <= '9' {
		// PP04 and PP04SP are the same numbered pump with a setpoint channel.
		device = strings.TrimSuffix(device, "SP")
		typ += "_SP"
	} else if len(device) > len(family)+1 {
		// D/Z/R are documented channel suffix patterns in this header.
		last := device[len(device)-1]
		if last == 'D' || last == 'Z' || last == 'R' {
			device = device[:len(device)-1]
			typ += "_" + string(last)
		}
	}
	return processColumn{site: "P" + match[1], device: device, typ: typ}, true
}

func swatTag(raw string) (processColumn, bool) {
	match := swatTagRE.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return processColumn{}, false
	}
	return processColumn{site: "P" + match[2], device: strings.ToUpper(raw), typ: strings.ToUpper(match[1])}, true
}
