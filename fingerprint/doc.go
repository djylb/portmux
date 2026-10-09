// Package fingerprint computes the JA4 and JA3 fingerprints of TLS
// ClientHellos parsed by tlshello, which identify the TLS library of a client,
// and filters routes by them. It is kept apart because it imports the
// standard library's hash functions, which programs that do not fingerprint
// need not carry.
package fingerprint
