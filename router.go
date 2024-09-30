package pingpong

import (
	"bytes"
	"net/http"
)

const (
	staticKind kind = iota
	paramKind
	anyKind

	paramLabel = byte(':')
	anyLabel   = byte('*')
)

// A registry place for all routes in a pingpong instance
type Router struct {
	tree     *node
	routes   map[string]*Route
	pingpong *Pingpong
}

// NewRouter returns a new Router instance.
func NewRouter(p *Pingpong) *Router {
	return &Router{
		tree: &node{
			methods: new(routeMethods),
		},
		routes:   map[string]*Route{},
		pingpong: p,
	}
}

func (r *Router) add(method, path, name string, h HandlerFunc) *Route {
	path = normalizePathSlash(path)
	r.insert(method, path, h)

	route := &Route{
		Method: method,
		Path:   path,
		Name:   name,
	}
	r.routes[method+path] = route
	return route
}

func (r *Router) insert(method, path string, h HandlerFunc) {
	path = normalizePathSlash(path)
	pnames := []string{} // Param names
	ppath := path        // Pristine path

	if h == nil && r.pingpong.StdLogger != nil {
		// FIXME: in future we should return error
		r.pingpong.StdLogger.Error("Adding route without handler function: %v:%v", method, path)
	}

	for i, lcpIndex := 0, len(path); i < lcpIndex; i++ {
		if path[i] == ':' {
			if i > 0 && path[i-1] == '\\' {
				path = path[:i-1] + path[i:]
				i--
				lcpIndex--
				continue
			}
			j := i + 1

			r.insertNode(method, path[:i], staticKind, routeMethod{})
			for ; i < lcpIndex && path[i] != '/'; i++ {
			}

			pnames = append(pnames, path[j:i])
			path = path[:j] + path[i:]
			i, lcpIndex = j, len(path)

			if i == lcpIndex {
				// path node is last fragment of route path. ie. `/users/:id`
				r.insertNode(method, path[:i], paramKind, routeMethod{ppath: ppath, pnames: pnames, handler: h})
			} else {
				r.insertNode(method, path[:i], paramKind, routeMethod{})
			}
		} else if path[i] == '*' {
			r.insertNode(method, path[:i], staticKind, routeMethod{})
			pnames = append(pnames, "*")
			r.insertNode(method, path[:i+1], anyKind, routeMethod{ppath: ppath, pnames: pnames, handler: h})
		}
	}

	r.insertNode(method, path, staticKind, routeMethod{ppath: ppath, pnames: pnames, handler: h})
}

func normalizePathSlash(path string) string {
	if path == "" {
		path = "/"
	} else if path[0] != '/' {
		path = "/" + path
	}
	return path
}

type node struct {
	methods    *routeMethods
	parent     *node
	paramChild *node
	anyChild   *node
	// notFoundHandler is handler registered with RouteNotFound method and is executed for 404 cases
	notFoundHandler *routeMethod
	prefix          string
	originalPath    string
	staticChildren  children
	paramsCount     int
	label           byte
	kind            kind
	// isLeaf indicates that node does not have child routes
	isLeaf bool
	// isHandler indicates that node has at least one handler registered to it
	isHandler bool
}

type kind uint8
type children []*node

type routeMethods struct {
	connect     *routeMethod
	delete      *routeMethod
	get         *routeMethod
	head        *routeMethod
	options     *routeMethod
	patch       *routeMethod
	post        *routeMethod
	propfind    *routeMethod
	put         *routeMethod
	trace       *routeMethod
	report      *routeMethod
	anyOther    map[string]*routeMethod
	allowHeader string
}

type routeMethod struct {
	handler HandlerFunc
	ppath   string
	pnames  []string
}

func (n *node) addMethod(method string, h *routeMethod) {
	switch method {
	case http.MethodConnect:
		n.methods.connect = h
	case http.MethodDelete:
		n.methods.delete = h
	case http.MethodGet:
		n.methods.get = h
	case http.MethodHead:
		n.methods.head = h
	case http.MethodOptions:
		n.methods.options = h
	case http.MethodPatch:
		n.methods.patch = h
	case http.MethodPost:
		n.methods.post = h
	case PROPFIND:
		n.methods.propfind = h
	case http.MethodPut:
		n.methods.put = h
	case http.MethodTrace:
		n.methods.trace = h
	case REPORT:
		n.methods.report = h
	case RouteNotFound:
		n.notFoundHandler = h
		return // RouteNotFound/404 is not considered as a handler so no further logic needs to be executed
	default:
		if n.methods.anyOther == nil {
			n.methods.anyOther = make(map[string]*routeMethod)
		}
		if h.handler == nil {
			delete(n.methods.anyOther, method)
		} else {
			n.methods.anyOther[method] = h
		}
	}

	n.methods.updateAllowHeader()
	n.isHandler = true
}

func (m *routeMethods) updateAllowHeader() {
	buf := new(bytes.Buffer)
	buf.WriteString(http.MethodOptions)

	if m.connect != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodConnect)
	}
	if m.delete != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodDelete)
	}
	if m.get != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodGet)
	}
	if m.head != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodHead)
	}
	if m.patch != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodPatch)
	}
	if m.post != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodPost)
	}
	if m.propfind != nil {
		buf.WriteString(", PROPFIND")
	}
	if m.put != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodPut)
	}
	if m.trace != nil {
		buf.WriteString(", ")
		buf.WriteString(http.MethodTrace)
	}
	if m.report != nil {
		buf.WriteString(", REPORT")
	}
	for method := range m.anyOther { // for simplicity, we use map and therefore order is not deterministic here
		buf.WriteString(", ")
		buf.WriteString(method)
	}
	m.allowHeader = buf.String()
}

func (r *Router) insertNode(method, path string, t kind, rm routeMethod) {
	// Adjust max param
	paramLen := len(rm.pnames)
	if *r.pingpong.maxParam < paramLen {
		*r.pingpong.maxParam = paramLen
	}

	currentNode := r.tree // Current node as root
	if currentNode == nil {
		panic("echo: invalid method")
	}
	search := path

	for {
		searchLen := len(search)
		prefixLen := len(currentNode.prefix)
		lcpLen := 0

		// LCP - Longest Common Prefix (https://en.wikipedia.org/wiki/LCP_array)
		max := prefixLen
		if searchLen < max {
			max = searchLen
		}
		for ; lcpLen < max && search[lcpLen] == currentNode.prefix[lcpLen]; lcpLen++ {
		}

		if lcpLen == 0 {
			// At root node
			currentNode.label = search[0]
			currentNode.prefix = search
			if rm.handler != nil {
				currentNode.kind = t
				currentNode.addMethod(method, &rm)
				currentNode.paramsCount = len(rm.pnames)
				currentNode.originalPath = rm.ppath
			}
			currentNode.isLeaf = currentNode.staticChildren == nil && currentNode.paramChild == nil && currentNode.anyChild == nil
		} else if lcpLen < prefixLen {
			// Split node into two before we insert new node.
			// This happens when we are inserting path that is submatch of any existing inserted paths.
			// For example, we have node `/test` and now are about to insert `/te/*`. In that case
			// 1. overlapping part is `/te` that is used as parent node
			// 2. `st` is part from existing node that is not matching - it gets its own node (child to `/te`)
			// 3. `/*` is the new part we are about to insert (child to `/te`)
			n := newNode(
				currentNode.kind,
				currentNode.prefix[lcpLen:],
				currentNode,
				currentNode.staticChildren,
				currentNode.originalPath,
				currentNode.methods,
				currentNode.paramsCount,
				currentNode.paramChild,
				currentNode.anyChild,
				currentNode.notFoundHandler,
			)
			// Update parent path for all children to new node
			for _, child := range currentNode.staticChildren {
				child.parent = n
			}
			if currentNode.paramChild != nil {
				currentNode.paramChild.parent = n
			}
			if currentNode.anyChild != nil {
				currentNode.anyChild.parent = n
			}

			// Reset parent node
			currentNode.kind = staticKind
			currentNode.label = currentNode.prefix[0]
			currentNode.prefix = currentNode.prefix[:lcpLen]
			currentNode.staticChildren = nil
			currentNode.originalPath = ""
			currentNode.methods = new(routeMethods)
			currentNode.paramsCount = 0
			currentNode.paramChild = nil
			currentNode.anyChild = nil
			currentNode.isLeaf = false
			currentNode.isHandler = false
			currentNode.notFoundHandler = nil

			// Only Static children could reach here
			currentNode.addStaticChild(n)

			if lcpLen == searchLen {
				// At parent node
				currentNode.kind = t
				if rm.handler != nil {
					currentNode.addMethod(method, &rm)
					currentNode.paramsCount = len(rm.pnames)
					currentNode.originalPath = rm.ppath
				}
			} else {
				// Create child node
				n = newNode(t, search[lcpLen:], currentNode, nil, "", new(routeMethods), 0, nil, nil, nil)
				if rm.handler != nil {
					n.addMethod(method, &rm)
					n.paramsCount = len(rm.pnames)
					n.originalPath = rm.ppath
				}
				// Only Static children could reach here
				currentNode.addStaticChild(n)
			}
			currentNode.isLeaf = currentNode.staticChildren == nil && currentNode.paramChild == nil && currentNode.anyChild == nil
		} else if lcpLen < searchLen {
			search = search[lcpLen:]
			c := currentNode.findChildWithLabel(search[0])
			if c != nil {
				// Go deeper
				currentNode = c
				continue
			}
			// Create child node
			n := newNode(t, search, currentNode, nil, rm.ppath, new(routeMethods), 0, nil, nil, nil)
			if rm.handler != nil {
				n.addMethod(method, &rm)
				n.paramsCount = len(rm.pnames)
			}

			switch t {
			case staticKind:
				currentNode.addStaticChild(n)
			case paramKind:
				currentNode.paramChild = n
			case anyKind:
				currentNode.anyChild = n
			}
			currentNode.isLeaf = currentNode.staticChildren == nil && currentNode.paramChild == nil && currentNode.anyChild == nil
		} else {
			// Node already exists
			if rm.handler != nil {
				currentNode.addMethod(method, &rm)
				currentNode.paramsCount = len(rm.pnames)
				currentNode.originalPath = rm.ppath
			}
		}
		return
	}
}

func newNode(
	t kind,
	pre string,
	p *node,
	sc children,
	originalPath string,
	methods *routeMethods,
	paramsCount int,
	paramChildren,
	anyChildren *node,
	notFoundHandler *routeMethod,
) *node {
	return &node{
		kind:            t,
		label:           pre[0],
		prefix:          pre,
		parent:          p,
		staticChildren:  sc,
		originalPath:    originalPath,
		methods:         methods,
		paramsCount:     paramsCount,
		paramChild:      paramChildren,
		anyChild:        anyChildren,
		isLeaf:          sc == nil && paramChildren == nil && anyChildren == nil,
		isHandler:       methods.isHandler(),
		notFoundHandler: notFoundHandler,
	}
}

func (n *node) addStaticChild(c *node) {
	n.staticChildren = append(n.staticChildren, c)
}

func (m *routeMethods) isHandler() bool {
	return m.connect != nil ||
		m.delete != nil ||
		m.get != nil ||
		m.head != nil ||
		m.options != nil ||
		m.patch != nil ||
		m.post != nil ||
		m.propfind != nil ||
		m.put != nil ||
		m.trace != nil ||
		m.report != nil ||
		len(m.anyOther) != 0
	// RouteNotFound/404 is not considered as a handler
}

func (n *node) findStaticChild(l byte) *node {
	for _, c := range n.staticChildren {
		if c.label == l {
			return c
		}
	}
	return nil
}

func (n *node) findChildWithLabel(l byte) *node {
	if c := n.findStaticChild(l); c != nil {
		return c
	}
	if l == paramLabel {
		return n.paramChild
	}
	if l == anyLabel {
		return n.anyChild
	}
	return nil
}
