package internal

import g "github.com/gosnmp/gosnmp"

func getMsgFlag(s string) g.SnmpV3MsgFlags {
	switch s {
	case "NoAuthNoPriv":
		return g.NoAuthNoPriv
	case "AuthNoPriv":
		return g.AuthNoPriv
	case "AuthPriv":
		return g.AuthPriv
	case "Reportable":
		return g.Reportable
	default:
		return g.NoAuthNoPriv
	}
}

func getAuthType(s string) g.SnmpV3AuthProtocol {
	switch s {
	case "MD5":
		return g.MD5
	case "SHA":
		return g.SHA
	case "SHA224", "SHA-224":
		return g.SHA224
	case "SHA256", "SHA-256":
		return g.SHA256
	case "SHA384", "SHA-384":
		return g.SHA384
	case "SHA512", "SHA-512":
		return g.SHA512
	default:
		return g.NoAuth
	}
}

func getPrivType(s string) g.SnmpV3PrivProtocol {
	switch s {
	case "DES":
		return g.DES
	case "AES", "AES-128":
		return g.AES
	case "AES192", "AES-192":
		return g.AES192
	case "AES256", "AES-256":
		return g.AES256
	case "AES192C", "AES-192C":
		return g.AES192C
	case "AES256C", "AES-256C":
		return g.AES256C
	default:
		return g.NoPriv
	}
}
