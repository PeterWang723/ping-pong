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

// WriteHeader sends an HTTP response header with status code. If WriteHeader is
// not called explicitly, the first call to Write will trigger an implicit
// WriteHeader(http.StatusOK). Thus explicit calls to WriteHeader are mainly
// used to send error codes.
func (r *Response) WriteHeader(code int) {
	if r.Committed {
		r.pingpong.Logger.Warn("response already comitted")
		return
	}
	r.Status = code
	for _, fn := range r.beforeFuncs {
		fn()
	}
	r.Writer.WriteHeader(r.Status)
	r.Committed = true
}

// Header returns the header map for the writer that will be sent by
// WriteHeader. Changing the header after a call to WriteHeader (or Write) has
// no effect unless the modified headers were declared as trailers by setting
// the "Trailer" header before the call to WriteHeader (see example)
// To suppress implicit response headers, set their value to nil.
// Example: https://golang.org/pkg/net/http/#example_ResponseWriter_trailers
func (r *Response) Header() http.Header {
	return r.Writer.Header()
}