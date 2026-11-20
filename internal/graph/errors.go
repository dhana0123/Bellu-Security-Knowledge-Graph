package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Class is the retry classification of a Graph_Store error.
type Class int

const (
	// ClassNone is returned for a nil error.
	ClassNone Class = iota
	// ClassTransient errors may succeed on retry.
	ClassTransient
	// ClassClient errors are caused by the request (syntax, constraint); retrying will not help.
	ClassClient
	// ClassFatal errors (auth, cancellation, timeout, unknown) must stop the caller.
	ClassFatal
)

func (c Class) String() string {
	switch c {
	case ClassNone:
		return "none"
	case ClassTransient:
		return "transient"
	case ClassClient:
		return "client"
	default:
		return "fatal"
	}
}

// Error wraps a driver error with its class. Its message never contains
// query parameters.
type Error struct {
	Class Class
	Code  string // Neo4j status code when known
	Err   error
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("graph: %s error (%s): %v", e.Class, e.Code, e.Err)
	}
	return fmt.Sprintf("graph: %s error: %v", e.Class, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Classify maps an error to a Class.
func Classify(err error) Class {
	if err == nil {
		return ClassNone
	}
	var ge *Error
	if errors.As(err, &ge) {
		return ge.Class
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ClassFatal
	}
	var ne *neo4j.Neo4jError
	if errors.As(err, &ne) {
		return classifyCode(ne.Code)
	}
	if neo4j.IsConnectivityError(err) {
		return ClassTransient
	}
	if neo4j.IsTransactionExecutionLimit(err) {
		return ClassTransient
	}
	return ClassFatal
}

func classifyCode(code string) Class {
	parts := strings.Split(code, ".")
	if len(parts) < 2 {
		return ClassFatal
	}
	switch parts[1] {
	case "TransientError":
		return ClassTransient
	case "ClientError":
		if len(parts) > 2 && parts[2] == "Security" {
			return ClassFatal
		}
		return ClassClient
	default:
		return ClassFatal
	}
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	var ge *Error
	if errors.As(err, &ge) {
		return err
	}
	out := &Error{Class: Classify(err), Err: err}
	var ne *neo4j.Neo4jError
	if errors.As(err, &ne) {
		out.Code = ne.Code
	}
	return out
}
