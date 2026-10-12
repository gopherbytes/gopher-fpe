package fpe

import "fmt"

type ErrorCode string

const (
	ErrInvalidInput     ErrorCode = "INVALID_INPUT"
	ErrInputTooShort    ErrorCode = "INPUT_TOO_SHORT"
	ErrInputTooLong     ErrorCode = "INPUT_TOO_LONG"
	ErrInvalidChar      ErrorCode = "INVALID_CHAR"
	ErrUnsupportedRadix ErrorCode = "UNSUPPORTED_RADIX"

	ErrKeyUnavailable ErrorCode = "KEY_UNAVAILABLE"
	ErrCipherBuild    ErrorCode = "CIPHER_BUILD_FAILED"
	ErrEncrypt        ErrorCode = "ENCRYPT_FAILED"
	ErrDecrypt        ErrorCode = "DECRYPT_FAILED"
)

type Error struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}

	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func NewError(code ErrorCode, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

func WrapError(code ErrorCode, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
