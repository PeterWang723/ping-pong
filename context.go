package pingpong

import (
	"log/slog"
	"net/http"
	"net/url"
	"sync"
)

type Context interface {
	// Response returns `*Response`.
	Response() *Response

	// Request returns `*http.Request`.
	Request() *http.Request
}

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
