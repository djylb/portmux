// Package ipmatch looks IP addresses up in sets of prefixes, such as block
// lists and office networks. Short sets are checked prefix by prefix, and long
// ones are merged into ranges and searched in logarithmic time. IPv4-mapped
// IPv6 addresses count as IPv4. The package uses only the standard library.
package ipmatch
