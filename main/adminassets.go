package main

import (
	_ "embed"
)

// The admin page, its stylesheet and its script are embedded from adminweb/.
//
// They live in their own files rather than as Go string constants because a
// 600-line JavaScript program inside a Go file gets no editor support: no
// syntax highlighting, no linting, no jump-to-definition, and every UI change
// shows up as a diff of the enclosing Go file. go:embed costs nothing at
// runtime and keeps the assets editable as what they are.
//
// There are still no external assets and no CDN: everything is served from
// this binary.

//go:embed adminweb/index.html
var indexHTML string

//go:embed adminweb/admin.css
var adminCSS string

//go:embed adminweb/admin.js
var adminJS string
