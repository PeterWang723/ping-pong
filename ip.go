package pingpong

import "net/http"

type IPExtractor func(*http.Request) string
