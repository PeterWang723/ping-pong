package pingpong

import "net/http"

// Response wraps an http.ResponseWriter and implements its interface to be used
// by an HTTP handler to construct an HTTP response.
// See: https://golang.org/pkg/net/http/#ResponseWriter
type Response struct {
	Writer      http.ResponseWriter
	pingpong    *Pingpong
	beforeFuncs []func()
	afterFuncs  []func()
	Status      int
	Size        int64
	Committed   bool
}

// Write implements io.Writer.
func (r *Response) Write(p []byte) (n int, err error) {
	panic("unimplemented")
}

// NewResponse creates a new instance of Response.
func NewResponse(w http.ResponseWriter, p *Pingpong) (r *Response) {
	return &Response{Writer: w, pingpong: p}
}

func (r *Response) reset(w http.ResponseWriter) {
	r.beforeFuncs = nil
	r.afterFuncs = nil
	r.Writer = w
	r.Size = 0
	r.Status = http.StatusOK
	r.Committed = false
}
