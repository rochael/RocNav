package service

import "errors"

var ErrForbidden = errors.New("forbidden")
var ErrNotFound = errors.New("not found")
var ErrUnauthorized = errors.New("unauthorized")