package mitm

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dop251/goja"
)

// scriptTimeout caps how long a single Quantumult X script may run before it
// is interrupted, so a stuck or infinite script can never stall the tunnel.
const scriptTimeout = 2 * time.Second

// Store is the minimal key-value contract behind $persistentStore.
type Store interface {
	Read(key string) (string, bool)
	Write(key, value string)
}

// ScriptEngine executes Quantumult X rewrite scripts against a request or
// response. Each evaluation gets a fresh goja runtime, so scripts cannot leak
// state across calls; persistent state goes through $persistentStore instead.
type ScriptEngine struct {
	// PersistentStore is an optional key-value store backing
	// $persistentStore.read/write. It may be nil, in which case writes are
	// silently dropped and reads return null.
	PersistentStore Store
	// Notify is an optional callback backing $notification.post. It may be nil.
	Notify func(title, subtitle, body string)
}

// ScriptResult is what a script produced, returned to the caller so it can
// apply rewrites to the in-flight request or response.
type ScriptResult struct {
	// Done is the object passed to $done({...}), or nil if the script ended
	// without calling $done.
	Done map[string]interface{}
}

// RunScript evaluates script against the given request and/or response. At
// least one of req/resp must be non-nil. The result object (the value handed
// to $done) is returned so the caller can apply any rewrites.
func (e *ScriptEngine) RunScript(script string, req *http.Request, resp *http.Response) (*ScriptResult, error) {
	vm := goja.New()

	if err := e.injectGlobals(vm, req, resp); err != nil {
		return nil, err
	}

	// Run with a hard timeout. goja.Interrupt is checked at JS bytecode
	// boundaries, so an infinite JS loop is still broken out of.
	timer := time.AfterFunc(scriptTimeout, func() {
		vm.Interrupt("mitm script timeout")
	})

	_, err := vm.RunString(script)
	timer.Stop()

	if err != nil {
		return nil, fmt.Errorf("mitm: script execution failed: %w", err)
	}

	return &ScriptResult{Done: e.collectDone(vm)}, nil
}

// injectGlobals wires the Quantumult X global API into the runtime.
func (e *ScriptEngine) injectGlobals(vm *goja.Runtime, req *http.Request, resp *http.Response) error {
	// $request mirrors the request being processed.
	reqObj := vm.NewObject()
	if req != nil {
		_ = reqObj.Set("url", req.URL.String())
		_ = reqObj.Set("method", req.Method)
		_ = reqObj.Set("headers", headerToMap(req.Header))
		_ = reqObj.Set("body", drainBody(req.Body))
	}
	_ = vm.Set("$request", reqObj)

	// $response mirrors the response being processed.
	respObj := vm.NewObject()
	if resp != nil {
		_ = respObj.Set("status", resp.StatusCode)
		_ = respObj.Set("headers", headerToMap(resp.Header))
		_ = respObj.Set("body", drainBody(resp.Body))
	}
	_ = vm.Set("$response", respObj)

	// $done(obj) is the exit seam: the script calls it to short-circuit or
	// return rewritten values. We capture its argument into $__done.
	_ = vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		var arg goja.Value = goja.Undefined()
		if len(call.Arguments) > 0 {
			arg = call.Argument(0)
		}
		_ = vm.Set("$__done", arg)
		return goja.Undefined()
	})

	// $persistentStore.read / .write
	store := vm.NewObject()
	_ = store.Set("read", func(call goja.FunctionCall) goja.Value {
		if e.PersistentStore == nil {
			return goja.Null()
		}
		key := call.Argument(0).String()
		if v, ok := e.PersistentStore.Read(key); ok {
			return vm.ToValue(v)
		}
		return goja.Null()
	})
	_ = store.Set("write", func(call goja.FunctionCall) goja.Value {
		if e.PersistentStore != nil {
			e.PersistentStore.Write(call.Argument(0).String(), call.Argument(1).String())
		}
		return goja.Undefined()
	})
	_ = vm.Set("$persistentStore", store)

	// $notification.post(title, subtitle, body)
	notification := vm.NewObject()
	_ = notification.Set("post", func(call goja.FunctionCall) goja.Value {
		if e.Notify != nil {
			title := call.Argument(0).String()
			subtitle := call.Argument(1).String()
			body := call.Argument(2).String()
			e.Notify(title, subtitle, body)
		}
		return goja.Undefined()
	})
	_ = vm.Set("$notification", notification)

	// console.log(...) — accepted and dropped by default.
	console := vm.NewObject()
	_ = console.Set("log", func(call goja.FunctionCall) goja.Value {
		return goja.Undefined()
	})
	_ = vm.Set("console", console)

	return nil
}

// collectDone reads back the value the script passed to $done, if any.
func (e *ScriptEngine) collectDone(vm *goja.Runtime) map[string]interface{} {
	v := vm.Get("$__done")
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	switch m := v.Export().(type) {
	case map[string]interface{}:
		return m
	case map[string]string:
		out := make(map[string]interface{}, len(m))
		for k, s := range m {
			out[k] = s
		}
		return out
	}
	return nil
}

// headerToMap converts an http.Header to a map of the first value per key,
// matching what Quantumult X exposes to scripts.
func headerToMap(h http.Header) map[string]string {
	if h == nil {
		return map[string]string{}
	}
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// drainBody reads and returns a body as a string. It does NOT close the body;
// the caller is responsible for the body's lifecycle. Returns "" for a nil
// body or a read error.
func drainBody(body io.ReadCloser) string {
	if body == nil {
		return ""
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return ""
	}
	return string(b)
}

// bodyCloser returns a new body closer for the given string, used when a
// script rewrites the request or response body.
func bodyCloser(s string) io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte(s)))
}
