package pingpong

import (
	"log/slog"
	"net/http"
	"net/url"
	"sync"
)

const (
	defaultMemory = 32 << 20 // 32 MB
	indexPage     = "index.html"
	defaultIndent = "  "
)

type Context interface {
	// Response returns `*Response`.
	Response() *Response

	// Request returns `*http.Request`.
	Request() *http.Request

	// Handler returns the matched handler by router.
	Handler() HandlerFunc

	// NoContent sends a response with no body and a status code.
	NoContent(code int) error

	// JSON sends a JSON response with status code.
	JSON(code int, i interface{}) error

	// QueryParams returns the query parameters as `url.Values`.
	QueryParams() url.Values

	// Set saves data in the context.
	Set(key string, val interface{})

	// Get retrieves data from the context.
	Get(key string) interface{}
}

const (
	// ContextKeyHeaderAllow is set by Router for getting value for `Allow` header in later stages of handler call chain.
	// Allow header is mandatory for status 405 (method not found) and useful for OPTIONS method requests.
	// It is added to context only when Router does not find matching method handler for request.
	ContextKeyHeaderAllow = "pingpong_header_allow"
)

type context struct {
	request  *http.Request
	response *Response
	query    url.Values
	pingpong *Pingpong

	logger  *slog.Logger
	store Map
	lock  sync.RWMutex

	// following fields are set by Router
	handler HandlerFunc

	// path is route path that Router matched. It is empty string where there is no route match.
	// Route registered with RouteNotFound is considered as a match and path therefore is not empty.
	path string

	// Usually echo.Echo is sizing pvalues but there could be user created middlewares that decide to
	// overwrite parameter by calling SetParamNames + SetParamValues.
	// When echo.Echo allocated that slice it length/capacity is tied to echo.Echo.maxParam value.
	//
	// It is important that pvalues size is always equal or bigger to pnames length.
	pvalues []string

	// pnames length is tied to param count for the matched route
	pnames []string
}

// Request implements Context.
func (c *context) Request() *http.Request {
	panic("unimplemented")
}

// Response implements Context.
func (c *context) Response() *Response {
	panic("unimplemented")
}

func (c *context) Reset(r *http.Request, w http.ResponseWriter) {
	c.request = r
	c.response.reset(w)
	c.query = nil
	c.handler = NotFoundHandler
	c.store = nil
	c.path = ""
	c.pnames = nil
	c.logger = nil
	// NOTE: Don't reset because it has to have length c.echo.maxParam (or bigger) at all times
	for i := 0; i < len(c.pvalues); i++ {
		c.pvalues[i] = ""
	}
}

func (c *context) Handler() HandlerFunc {
	return c.handler
}

func (c *context) NoContent(code int) error {
	c.response.WriteHeader(code)
	return nil
}

func (c *context) JSON(code int, i interface{}) (err error) {
	indent := ""
	if _, pretty := c.QueryParams()["pretty"]; c.pingpong.Debug || pretty {
		indent = defaultIndent
	}
	return c.json(code, i, indent)
}

func (c *context) json(code int, i interface{}, indent string) error {
	c.writeContentType(MIMEApplicationJSON)
	c.response.Status = code
	return c.pingpong.JSONSerializer.Serialize(c, i, indent)
}

func (c *context) writeContentType(value string) {
	header := c.Response().Header()
	if header.Get(HeaderContentType) == "" {
		header.Set(HeaderContentType, value)
	}
}

func (c *context) QueryParams() url.Values {
	if c.query == nil {
		c.query = c.request.URL.Query()
	}
	return c.query
}

func (c *context) Set(key string, val interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.store == nil {
		c.store = make(Map)
	}
	c.store[key] = val
}

func (c *context) Get(key string) interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.store[key]
}