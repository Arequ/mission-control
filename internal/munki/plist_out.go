package munki

import "howett.net/plist"

// MarshalPkginfoPlist renders a pkginfo dictionary as XML plist.
func MarshalPkginfoPlist(info map[string]any) ([]byte, error) {
	return plist.MarshalIndent(info, plist.XMLFormat, "\t")
}
