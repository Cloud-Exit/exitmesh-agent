package protocol

import "errors"

// Rejection reasons. Their Code values are the wire codes of SPEC section 9.4.
var (
	ErrMalformed        = &Error{Code: "malformed"}
	ErrTooLarge         = &Error{Code: "too_large"}
	ErrUnsupportedField = &Error{Code: "unsupported_field"}
	ErrInvalidValue     = &Error{Code: "invalid_value"}
	ErrInvalidChain     = &Error{Code: "invalid_chain"}
	ErrInvalidOp        = &Error{Code: "invalid_op"}
	ErrInvalidStateHash = &Error{Code: "invalid_state_hash"}
	ErrUnavailable      = &Error{Code: "unavailable"}
	ErrFold             = &Error{Code: "fold"}
)

// Error is a protocol rejection class; wrap it with fmt.Errorf("%w: ...").
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

// CodeOf returns the protocol code of err, or "" if err is not a protocol error.
func CodeOf(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
