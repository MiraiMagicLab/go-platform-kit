package errors

// English debug messages keyed by Mirai Java MessageCodes (Mxxxx).
// Several kit constants share one wire code; list each code once.
var commonMessages = map[string]string{
	// Success
	CodeSuccess:   "Success",
	CodeCreated:   "Resource created",
	CodeUpdated:   "Resource updated",
	CodeDeleted:   "Resource deleted",
	CodeNoContent: "No content",

	// Mirai MessageCodes
	"M0100": "Invalid request",
	"M0105": "Rate limit exceeded",
	"M0200": "Authentication required",
	"M0201": "Token expired",
	"M0202": "Invalid token",
	"M0203": "Invalid credentials",
	"M0250": "Permission denied",
	"M0251": "Account is locked",
	"M0252": "Account is disabled",
	"M0300": "Resource not found",
	"M0301": "Resource conflict",
	"M0400": "Business rule violation",
	"M0800": "External service error",
	"M0900": "Internal server error",
}
