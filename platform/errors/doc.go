// Package errors provides stable platform error codes (M00xxxx), message registry,
// and error mapping utilities for MiraiMagicLab backend services.
//
// Error codes follow the format: M + 2-digit product + 2-digit category + 3-digit sequence.
// Success codes use the S prefix with the same structure.
//
// Use [RegisterMessages] at startup to add domain-specific messages.
// Use [ErrorMapper] and [WriteError] to translate domain errors into stable API responses.
package errors
