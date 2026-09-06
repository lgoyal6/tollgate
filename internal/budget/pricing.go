package budget

import (
	"encoding/json"
	"strings"
)

// Prices are USD micros per million tokens, the unit providers actually publish, so
// a price here can be checked against a pricing page without arithmetic.
//
// This table is deliberately small and explicit. An unknown model is not guessed at:
// EstimateUpperBound reports ok=false and the gateway degrades to tracking instead of
// enforcing, because refusing a request on a made-up price is worse than not enforcing.
type Price struct {
	InputPerMTok  int64
	OutputPerMTok int64
}

var prices = map[string]Price{
	// Anthropic
	"claude-opus-5":    {InputPerMTok: 15_000_000, OutputPerMTok: 75_000_000},
	"claude-sonnet-5":  {InputPerMTok: 3_000_000, OutputPerMTok: 15_000_000},
	"claude-haiku-4-5": {InputPerMTok: 1_000_000, OutputPerMTok: 5_000_000},
	"claude-3-5-haiku": {InputPerMTok: 800_000, OutputPerMTok: 4_000_000},
	// OpenAI
	"gpt-4o":      {InputPerMTok: 2_500_000, OutputPerMTok: 10_000_000},
	"gpt-4o-mini": {InputPerMTok: 150_000, OutputPerMTok: 600_000},
}

// PriceFor resolves a model id to a price, matching on the longest registered
// prefix so dated snapshots ("claude-sonnet-5-20260101") inherit the base price.
func PriceFor(model string) (Price, bool) {
	if p, ok := prices[model]; ok {
		return p, true
	}
	var best string
	for name := range prices {
		if strings.HasPrefix(model, name) && len(name) > len(best) {
			best = name
		}
	}
	if best == "" {
		return Price{}, false
	}
	return prices[best], true
}

// RequestShape is what the gateway can learn about cost before forwarding.
type RequestShape struct {
	Model     string
	MaxTokens int64 // the caller's own output ceiling
	InputTok  int64 // estimated from body size when not declared
}

// EstimateUpperBound returns the most this request can cost, and whether that bound
// is enforceable at all.
//
// ok=false means the gateway must NOT refuse on budget: either the model has no known
// price or the caller declared no output ceiling, and without both there is no upper
// bound to hold. A request that can emit unbounded output cannot be bounded in dollars
// by inspecting it - that is a real limit of this design, not an oversight.
func EstimateUpperBound(s RequestShape) (int64, bool) {
	p, ok := PriceFor(s.Model)
	if !ok || s.MaxTokens <= 0 {
		return 0, false
	}
	in := s.InputTok * p.InputPerMTok / 1_000_000
	out := s.MaxTokens * p.OutputPerMTok / 1_000_000
	return in + out, true
}

// Cost converts reported usage into micros. Used at settle time, when the provider
// has told us what actually happened.
func Cost(model string, inputTok, outputTok int64) (int64, bool) {
	p, ok := PriceFor(model)
	if !ok {
		return 0, false
	}
	return inputTok*p.InputPerMTok/1_000_000 + outputTok*p.OutputPerMTok/1_000_000, true
}

// ShapeFromBody reads the model and output ceiling out of a chat-completions style
// request body. It tolerates both the Anthropic (`max_tokens`) and OpenAI
// (`max_completion_tokens`) spellings and never fails the request on a parse error -
// an unparseable body simply yields an unenforceable shape.
func ShapeFromBody(body []byte) RequestShape {
	var req struct {
		Model               string `json:"model"`
		MaxTokens           int64  `json:"max_tokens"`
		MaxCompletionTokens int64  `json:"max_completion_tokens"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return RequestShape{}
	}
	maxTok := req.MaxTokens
	if maxTok == 0 {
		maxTok = req.MaxCompletionTokens
	}
	return RequestShape{
		Model:     req.Model,
		MaxTokens: maxTok,
		// ~4 bytes per token is the usual rough rule. It is an ESTIMATE and only
		// feeds the conservative hold; settlement uses the provider's real count.
		InputTok: int64(len(body)) / 4,
	}
}

// UsageFromResponse pulls the provider's own token counts out of a response body.
// Returns ok=false when the response carries no usage block (streaming without a
// final usage frame, or an error response), which is what drives MarkUncertain.
func UsageFromResponse(body []byte) (inputTok, outputTok int64, ok bool) {
	var resp struct {
		Usage struct {
			InputTokens      int64 `json:"input_tokens"`
			OutputTokens     int64 `json:"output_tokens"`
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, false
	}
	u := resp.Usage
	in, out := u.InputTokens, u.OutputTokens
	if in == 0 && out == 0 {
		in, out = u.PromptTokens, u.CompletionTokens
	}
	if in == 0 && out == 0 {
		return 0, 0, false
	}
	return in, out, true
}
