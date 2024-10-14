package pingpong

// Binder is the interface that wraps the Bind method.
type Binder interface {
	Bind(i interface{}, c Context) error
}

// DefaultBinder is the default implementation of the Binder interface.
type DefaultBinder struct{}

// Bind implements the `Binder#Bind` function.
// Binding is done in following order: 1) path params; 2) query params; 3) request body. Each step COULD override previous
// step binded values. For single source binding use their own methods BindBody, BindQueryParams, BindPathParams.
func (b *DefaultBinder) Bind(i interface{}, c Context) (err error) {
	panic("unimplemented")
}
