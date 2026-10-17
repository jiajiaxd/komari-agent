package server

import (
	"encoding/json"
	"fmt"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

type httpStatusError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *httpStatusError) Error() string {
	if e == nil {
		return ""
	}
	if e.Body != "" {
		return fmt.Sprintf("status code: %d,%s", e.StatusCode, e.Body)
	}
	if e.Status != "" {
		return e.Status
	}
	return fmt.Sprintf("status code: %d", e.StatusCode)
}

// RPCCallError is returned when the server answers with a JSON-RPC error object.
type RPCCallError struct {
	Code    int
	Message string
}

func (e *RPCCallError) Error() string {
	return fmt.Sprintf("v2 rpc error %d: %s", e.Code, e.Message)
}

func parseV2Response(body []byte) (*v2.Response, error) {
	var rpcResp v2.Response
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid v2 JSON-RPC response: %w, body: %s", err, bodySnippet(body))
	}
	if rpcResp.JSONRPC != v2.Version {
		return nil, fmt.Errorf("invalid v2 JSON-RPC version %q, body: %s", rpcResp.JSONRPC, bodySnippet(body))
	}
	if rpcResp.Error != nil {
		return &rpcResp, &RPCCallError{Code: rpcResp.Error.Code, Message: rpcResp.Error.Message}
	}
	return &rpcResp, nil
}

func bodySnippet(body []byte) string {
	const max = 120
	if len(body) > max {
		body = body[:max]
	}
	return fmt.Sprintf("%q", string(body))
}
