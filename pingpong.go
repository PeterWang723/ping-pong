package pingpong

import (
	stdContext "context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdLog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Pingpong is the top-level framework instance
// Evrything happens in this web server or from this instance
type Pingpong struct {
	filesystem
	common

	// create a Read and write mutex in the beginning
	startupMutex sync.RWMutex

	premiddleware []MiddlewareFunc
	middleware    []MiddlewareFunc
	maxParam      *int
	router        *Router
	routers       map[string]*Router
	pool          sync.Pool

	StdLogger        *stdLog.Logger
	Logger           *slog.Logger
	Server           *http.Server
	TLSServer        *http.Server
	Listener         net.Listener
	TLSListener      net.Listener
	AutoTLSManager   autocert.Manager
	HTTPErrorHandler HTTPErrorHandler
	Binder           Binder
	JSONSerializer   JSONSerializer
	Validator        Validator
	Renderer         Renderer
	IPExtractor      IPExtractor
	ListenerNetwork  string

	// OnAddRouteHandler is called when PingPong adds new route to specific host router.
	OnAddRouteHandler func(host string, route Route, handler HandlerFunc, middleware []MiddlewareFunc)
	DisableHTTP2      bool
	Debug             bool
	HideBanner        bool
	HidePort          bool
}

// common structure for Pingpong & Groups
type common struct{}

// MiddlewareFunc defines a function to process middleware.
type MiddlewareFunc func(next HandlerFunc) HandlerFunc

// HTTPErrorHandler is a centralized HTTP error handler.
type HTTPErrorHandler func(err error, c Context)

// JSONSerializer is the interface that encodes and decodes JSON to and from interfaces.
type JSONSerializer interface {
	Serialize(c Context, i interface{}, indent string) error
	Deserialize(c Context, i interface{}) error
}

// Validator is the interface that wraps the Validate function.
type Validator interface {
	Validate(i interface{}) error
}

// Renderer is the interface that wraps the Render function.
type Renderer interface {
	Render(io.Writer, string, interface{}, Context) error
}

// Route contains a handler and information for matching against requests.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Name   string `json:"name"`
}

// HandlerFunc defines a function to serve HTTP requests.
type HandlerFunc func(c Context) error

const (
	charsetUTF8 = "charset=UTF-8"
	// PROPFIND Method can be used on collection and property resources.
	PROPFIND = "PROPFIND"
	// REPORT Method can be used to get information about a resource, see rfc 3253
	REPORT = "REPORT"
	// RouteNotFound is special method type for routes handling "route not found" (404) cases
	RouteNotFound = "echo_route_not_found"
)

// MIME types
const (
	// MIMEApplicationJSON JavaScript Object Notation (JSON) https://www.rfc-editor.org/rfc/rfc8259
	MIMEApplicationJSON = "application/json"

	MIMEApplicationJavaScript            = "application/javascript"
	MIMEApplicationJavaScriptCharsetUTF8 = MIMEApplicationJavaScript + "; " + charsetUTF8
	MIMEApplicationXML                   = "application/xml"
	MIMEApplicationXMLCharsetUTF8        = MIMEApplicationXML + "; " + charsetUTF8
	MIMETextXML                          = "text/xml"
	MIMETextXMLCharsetUTF8               = MIMETextXML + "; " + charsetUTF8
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"
	MIMEApplicationProtobuf              = "application/protobuf"
	MIMEApplicationMsgpack               = "application/msgpack"
	MIMETextHTML                         = "text/html"
	MIMETextHTMLCharsetUTF8              = MIMETextHTML + "; " + charsetUTF8
	MIMETextPlain                        = "text/plain"
	MIMETextPlainCharsetUTF8             = MIMETextPlain + "; " + charsetUTF8
	MIMEMultipartForm                    = "multipart/form-data"
	MIMEOctetStream                      = "application/octet-stream"
)

// Headers
const (
	HeaderAccept         = "Accept"
	HeaderAcceptEncoding = "Accept-Encoding"
	// HeaderAllow is the name of the "Allow" header field used to list the set of methods
	// advertised as supported by the target resource. Returning an Allow header is mandatory
	// for status 405 (method not found) and useful for the OPTIONS method in responses.
	// See RFC 7231: https://datatracker.ietf.org/doc/html/rfc7231#section-7.4.1
	HeaderAllow               = "Allow"
	HeaderAuthorization       = "Authorization"
	HeaderContentDisposition  = "Content-Disposition"
	HeaderContentEncoding     = "Content-Encoding"
	HeaderContentLength       = "Content-Length"
	HeaderContentType         = "Content-Type"
	HeaderCookie              = "Cookie"
	HeaderSetCookie           = "Set-Cookie"
	HeaderIfModifiedSince     = "If-Modified-Since"
	HeaderLastModified        = "Last-Modified"
	HeaderLocation            = "Location"
	HeaderRetryAfter          = "Retry-After"
	HeaderUpgrade             = "Upgrade"
	HeaderVary                = "Vary"
	HeaderWWWAuthenticate     = "WWW-Authenticate"
	HeaderXForwardedFor       = "X-Forwarded-For"
	HeaderXForwardedProto     = "X-Forwarded-Proto"
	HeaderXForwardedProtocol  = "X-Forwarded-Protocol"
	HeaderXForwardedSsl       = "X-Forwarded-Ssl"
	HeaderXUrlScheme          = "X-Url-Scheme"
	HeaderXHTTPMethodOverride = "X-HTTP-Method-Override"
	HeaderXRealIP             = "X-Real-Ip"
	HeaderXRequestID          = "X-Request-Id"
	HeaderXCorrelationID      = "X-Correlation-Id"
	HeaderXRequestedWith      = "X-Requested-With"
	HeaderServer              = "Server"
	HeaderOrigin              = "Origin"
	HeaderCacheControl        = "Cache-Control"
	HeaderConnection          = "Connection"

	// Access control
	HeaderAccessControlRequestMethod    = "Access-Control-Request-Method"
	HeaderAccessControlRequestHeaders   = "Access-Control-Request-Headers"
	HeaderAccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods     = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	HeaderAccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	HeaderAccessControlMaxAge           = "Access-Control-Max-Age"

	// Security
	HeaderStrictTransportSecurity         = "Strict-Transport-Security"
	HeaderXContentTypeOptions             = "X-Content-Type-Options"
	HeaderXXSSProtection                  = "X-XSS-Protection"
	HeaderXFrameOptions                   = "X-Frame-Options"
	HeaderContentSecurityPolicy           = "Content-Security-Policy"
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"
	HeaderXCSRFToken                      = "X-CSRF-Token"
	HeaderReferrerPolicy                  = "Referrer-Policy"
)

// head of string when you run this server firstly
const (
	// Version of Echo
	Version = "0.0.1"
	website = "https://github.com/PeterWang723/ping-pong"
	banner  = `
PINGPONG%s
High performance, minimalist Go web framework
%s
____________________________________O/_______
                                    O\
`
)

// http methods slices
var methods = [...]string{
	http.MethodConnect,
	http.MethodDelete,
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPatch,
	http.MethodPost,
	PROPFIND,
	http.MethodPut,
	http.MethodTrace,
	REPORT,
}

// Errors
var (
	ErrBadRequest                    = NewHTTPError(http.StatusBadRequest)                    // HTTP 400 Bad Request
	ErrUnauthorized                  = NewHTTPError(http.StatusUnauthorized)                  // HTTP 401 Unauthorized
	ErrPaymentRequired               = NewHTTPError(http.StatusPaymentRequired)               // HTTP 402 Payment Required
	ErrForbidden                     = NewHTTPError(http.StatusForbidden)                     // HTTP 403 Forbidden
	ErrNotFound                      = NewHTTPError(http.StatusNotFound)                      // HTTP 404 Not Found
	ErrMethodNotAllowed              = NewHTTPError(http.StatusMethodNotAllowed)              // HTTP 405 Method Not Allowed
	ErrNotAcceptable                 = NewHTTPError(http.StatusNotAcceptable)                 // HTTP 406 Not Acceptable
	ErrProxyAuthRequired             = NewHTTPError(http.StatusProxyAuthRequired)             // HTTP 407 Proxy AuthRequired
	ErrRequestTimeout                = NewHTTPError(http.StatusRequestTimeout)                // HTTP 408 Request Timeout
	ErrConflict                      = NewHTTPError(http.StatusConflict)                      // HTTP 409 Conflict
	ErrGone                          = NewHTTPError(http.StatusGone)                          // HTTP 410 Gone
	ErrLengthRequired                = NewHTTPError(http.StatusLengthRequired)                // HTTP 411 Length Required
	ErrPreconditionFailed            = NewHTTPError(http.StatusPreconditionFailed)            // HTTP 412 Precondition Failed
	ErrStatusRequestEntityTooLarge   = NewHTTPError(http.StatusRequestEntityTooLarge)         // HTTP 413 Payload Too Large
	ErrRequestURITooLong             = NewHTTPError(http.StatusRequestURITooLong)             // HTTP 414 URI Too Long
	ErrUnsupportedMediaType          = NewHTTPError(http.StatusUnsupportedMediaType)          // HTTP 415 Unsupported Media Type
	ErrRequestedRangeNotSatisfiable  = NewHTTPError(http.StatusRequestedRangeNotSatisfiable)  // HTTP 416 Range Not Satisfiable
	ErrExpectationFailed             = NewHTTPError(http.StatusExpectationFailed)             // HTTP 417 Expectation Failed
	ErrTeapot                        = NewHTTPError(http.StatusTeapot)                        // HTTP 418 I'm a teapot
	ErrMisdirectedRequest            = NewHTTPError(http.StatusMisdirectedRequest)            // HTTP 421 Misdirected Request
	ErrUnprocessableEntity           = NewHTTPError(http.StatusUnprocessableEntity)           // HTTP 422 Unprocessable Entity
	ErrLocked                        = NewHTTPError(http.StatusLocked)                        // HTTP 423 Locked
	ErrFailedDependency              = NewHTTPError(http.StatusFailedDependency)              // HTTP 424 Failed Dependency
	ErrTooEarly                      = NewHTTPError(http.StatusTooEarly)                      // HTTP 425 Too Early
	ErrUpgradeRequired               = NewHTTPError(http.StatusUpgradeRequired)               // HTTP 426 Upgrade Required
	ErrPreconditionRequired          = NewHTTPError(http.StatusPreconditionRequired)          // HTTP 428 Precondition Required
	ErrTooManyRequests               = NewHTTPError(http.StatusTooManyRequests)               // HTTP 429 Too Many Requests
	ErrRequestHeaderFieldsTooLarge   = NewHTTPError(http.StatusRequestHeaderFieldsTooLarge)   // HTTP 431 Request Header Fields Too Large
	ErrUnavailableForLegalReasons    = NewHTTPError(http.StatusUnavailableForLegalReasons)    // HTTP 451 Unavailable For Legal Reasons
	ErrInternalServerError           = NewHTTPError(http.StatusInternalServerError)           // HTTP 500 Internal Server Error
	ErrNotImplemented                = NewHTTPError(http.StatusNotImplemented)                // HTTP 501 Not Implemented
	ErrBadGateway                    = NewHTTPError(http.StatusBadGateway)                    // HTTP 502 Bad Gateway
	ErrServiceUnavailable            = NewHTTPError(http.StatusServiceUnavailable)            // HTTP 503 Service Unavailable
	ErrGatewayTimeout                = NewHTTPError(http.StatusGatewayTimeout)                // HTTP 504 Gateway Timeout
	ErrHTTPVersionNotSupported       = NewHTTPError(http.StatusHTTPVersionNotSupported)       // HTTP 505 HTTP Version Not Supported
	ErrVariantAlsoNegotiates         = NewHTTPError(http.StatusVariantAlsoNegotiates)         // HTTP 506 Variant Also Negotiates
	ErrInsufficientStorage           = NewHTTPError(http.StatusInsufficientStorage)           // HTTP 507 Insufficient Storage
	ErrLoopDetected                  = NewHTTPError(http.StatusLoopDetected)                  // HTTP 508 Loop Detected
	ErrNotExtended                   = NewHTTPError(http.StatusNotExtended)                   // HTTP 510 Not Extended
	ErrNetworkAuthenticationRequired = NewHTTPError(http.StatusNetworkAuthenticationRequired) // HTTP 511 Network Authentication Required

	ErrValidatorNotRegistered = errors.New("validator not registered")
	ErrRendererNotRegistered  = errors.New("renderer not registered")
	ErrInvalidRedirectCode    = errors.New("invalid redirect status code")
	ErrCookieNotFound         = errors.New("cookie not found")
	ErrInvalidCertOrKeyType   = errors.New("invalid cert or key type, must be string or []byte")
	ErrInvalidListenerNetwork = errors.New("invalid listener network")
)

func NewHTTPError(code int, message ...interface{}) *HTTPError {
	he := &HTTPError{Code: code, Message: http.StatusText(code)}
	if len(message) > 0 {
		he.Message = message[0]
	}
	return he
}

// HTTPError represents an error that occurred while handling a request.
type HTTPError struct {
	Internal error       `json:"-"` // Stores the error returned by an external dependency
	Message  interface{} `json:"message"`
	Code     int         `json:"-"`
}

// Error implements error.
func (h *HTTPError) Error() string {
	panic("unimplemented")
}

// create a new instance for PingPong
func New() (p *Pingpong) {
	p = &Pingpong{
		filesystem: createFilesystem(),
		Server:     new(http.Server),
		TLSServer:  new(http.Server),
		AutoTLSManager: autocert.Manager{
			Prompt: autocert.AcceptTOS,
		},
		maxParam:        new(int),
		ListenerNetwork: "tcp",
	}
	p.Server.Handler = p
	p.TLSServer.Handler = p
	p.HTTPErrorHandler = p.DefaultHTTPErrorHandler
	p.Binder = &DefaultBinder{}
	p.JSONSerializer = &DefaultJSONSerializer{}
	p.StdLogger = stdLog.New(os.Stdout, "SERVER_ERROR: ", stdLog.LstdFlags)
	p.pool.New = func() interface{} {
		return p.NewContext(nil, nil)
	}
	p.router = NewRouter(p)
	p.routers = map[string]*Router{}
	return
}

// Pre adds middleware to the chain which is run before router.
func (p *Pingpong) Pre(middleware ...MiddlewareFunc) {
	p.premiddleware = append(p.premiddleware, middleware...)
}

// Use adds middleware to the chain which is run after router.
func (p *Pingpong) Use(middleware ...MiddlewareFunc) {
	p.middleware = append(p.middleware, middleware...)
}

// GET registers a new GET route for a path with matching handler in the router
// with optional route-level middleware.
func (p *Pingpong) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return p.Add(http.MethodGet, path, h, m...)
}

// Map defines a generic map of type `map[string]interface{}`.
type Map map[string]interface{}

// NewContext returns a Context instance.
func (p *Pingpong) NewContext(r *http.Request, w http.ResponseWriter) Context {
	return &context{
		request:  r,
		response: NewResponse(w, p),
		store:    make(Map),
		pingpong: p,
		pvalues:  make([]string, *p.maxParam),
		handler:  NotFoundHandler,
	}
}

// NotFoundHandler is the handler that router uses in case there was no matching route found. Returns an error that results
// HTTP 404 status code.
var NotFoundHandler = func(c Context) error {
	return ErrNotFound
}

// ServeHTTP implements `http.Handler` interface, which serves HTTP requests.
func (p *Pingpong) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Acquire context
	c := p.pool.Get().(*context)
	c.Reset(r, w)
	
	var h HandlerFunc

	if p.premiddleware == nil {
		p.findRouter(r.Host).Find(r.Method, GetPath(r), c)
		h = c.Handler()
		h = applyMiddleware(h, p.middleware...)
	} else {
		h = func(c Context) error {
			p.findRouter(r.Host).Find(r.Method, GetPath(r), c)
			h := c.Handler()
			h = applyMiddleware(h, p.middleware...)
			return h(c)
		}
		h = applyMiddleware(h, p.premiddleware...)
	}

	// Execute chain
	if err := h(c); err != nil {
		p.HTTPErrorHandler(err, c)
	}

	// Release context
	p.pool.Put(c)
}

// GetPath returns RawPath, if it's empty returns Path from URL
// Difference between RawPath and Path is:
//   - Path is where request path is stored. Value is stored in decoded form: /%47%6f%2f becomes /Go/.
//   - RawPath is an optional field which only gets set if the default encoding is different from Path.
func GetPath(r *http.Request) string {
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	return path
}

// SetInternal sets error to HTTPError.Internal
func (he *HTTPError) SetInternal(err error) *HTTPError {
	he.Internal = err
	return he
}


// DefaultHTTPErrorHandler is the default HTTP error handler. It sends a JSON response
// with status code.
//
// NOTE: In case errors happens in middleware call-chain that is returning from handler (which did not return an error).
// When handler has already sent response (ala c.JSON()) and there is error in middleware that is returning from
// handler. Then the error that global error handler received will be ignored because we have already "committed" the
// response and status code header has been sent to the client.
func (p *Pingpong) DefaultHTTPErrorHandler(err error, c Context) {

	if c.Response().Committed {
		return
	}

	he, ok := err.(*HTTPError)
	if ok {
		if he.Internal != nil {
			if herr, ok := he.Internal.(*HTTPError); ok {
				he = herr
			}
		}
	} else {
		he = &HTTPError{
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}
	}

	// Issue #1426
	code := he.Code
	message := he.Message

	switch m := he.Message.(type) {
	case string:
		if p.Debug {
			message = Map{"message": m, "error": err.Error()}
		} else {
			message = Map{"message": m}
		}
	case json.Marshaler:
		// do nothing - this type knows how to format itself to JSON
	case error:
		message = Map{"message": m.Error()}
	}

	// Send response
	if c.Request().Method == http.MethodHead { // Issue #608
		err = c.NoContent(he.Code)
	} else {
		err = c.JSON(code, message)
	}
	if err != nil {
		p.Logger.Error(err.Error())
	}
}

// Add registers a new route for an HTTP method and path with matching handler
// in the router with optional route-level middleware.
func (p *Pingpong) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	return p.add("", method, path, handler, middleware...)
}

func (p *Pingpong) add(host, method, path string, handler HandlerFunc, middlewares ...MiddlewareFunc) *Route {
	router := p.findRouter(host)
	//FIXME: when handler+middleware are both nil ... make it behave like handler removal
	name := handlerName(handler)
	route := router.add(method, path, name, func(c Context) error {
		h := applyMiddleware(handler, middlewares...)
		return h(c)
	})

	if p.OnAddRouteHandler != nil {
		p.OnAddRouteHandler(host, *route, handler, middlewares)
	}

	return route
}

func (p *Pingpong) findRouter(host string) *Router {
	if len(p.routers) > 0 {
		if r, ok := p.routers[host]; ok {
			return r
		}
	}
	return p.router
}

func handlerName(h HandlerFunc) string {
	t := reflect.ValueOf(h).Type()
	if t.Kind() == reflect.Func {
		return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	}
	return t.String()
}

// Start starts an HTTP server.
func (p *Pingpong) Start(address string) error {
	p.startupMutex.Lock()
	defer p.startupMutex.Unlock()
	p.Server.Addr = address
	if err := p.configureServer(p.Server); err != nil {
		return err
	}
	return p.Server.Serve(p.Listener)
}

func (p *Pingpong) configureServer(s *http.Server) error {
	// Setup

	s.ErrorLog = p.StdLogger
	s.Handler = p
	var handler *slog.TextHandler
	if p.Debug {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError,
		})
	}
	p.Logger = slog.New(handler)

	if !p.HideBanner {
		fmt.Printf(banner)
	}

	if s.TLSConfig == nil {
		if p.Listener == nil {
			l, err := newListener(s.Addr, p.ListenerNetwork)
			if err != nil {
				return err
			}
			p.Listener = l
		}
		if !p.HidePort {
			fmt.Printf("⇨ http server started on %s\n", p.Listener.Addr())
		}
		return nil
	}
	if p.TLSListener == nil {
		l, err := newListener(s.Addr, p.ListenerNetwork)
		if err != nil {
			return err
		}
		p.TLSListener = tls.NewListener(l, s.TLSConfig)
	}
	if !p.HidePort {
		fmt.Printf("⇨ https server started on %s\n", p.TLSListener.Addr())
	}
	return nil
}

func newListener(address, network string) (*tcpKeepAliveListener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrInvalidListenerNetwork
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &tcpKeepAliveListener{l.(*net.TCPListener)}, nil
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func applyMiddleware(h HandlerFunc, middleware ...MiddlewareFunc) HandlerFunc {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// MethodNotAllowedHandler is the handler thar router uses in case there was no matching route found but there was
// another matching routes for that requested URL. Returns an error that results HTTP 405 Method Not Allowed status code.
var MethodNotAllowedHandler = func(c Context) error {
	// See RFC 7231 section 7.4.1: An origin server MUST generate an Allow field in a 405 (Method Not Allowed)
	// response and MAY do so in any other response. For disabled resources an empty Allow header may be returned
	routerAllowMethods, ok := c.Get(ContextKeyHeaderAllow).(string)
	if ok && routerAllowMethods != "" {
		c.Response().Header().Set(HeaderAllow, routerAllowMethods)
	}
	return ErrMethodNotAllowed
}