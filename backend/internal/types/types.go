package types

import "time"

type ProcessRequest struct {
	Payload   string `json:"payload" binding:"required"`
	PayloadID string `json:"payload_id" binding:"required"`
}

type ProcessResponse struct {
	Result string `json:"result"`
}

type SessionState struct {
	OriginalText string
	MaskedText   string
	ExpiresAt    time.Time
}

type Span struct {
	Start int
	End   int
	Type  string
}
