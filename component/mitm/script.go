package mitm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
)

const (
	// scriptTimeout caps how long a single Quantumult X script may run before
	// it is interrupted, so a stuck or infinite script can never stall the
	// tunnel. Timers a script scheduled are bounded by the same budget.
	scriptTimeout = 2 * time.Second
	// scriptFetchTimeout is the default $task.fetch timeout, matching the
	// value Quantumult X documents.
	scriptFetchTimeout = 10 * time.Second
)

// Store is the minimal key-value contract behind $persistentStore and $prefs.
type Store interface {
	Read(key string) (string, bool)
	Write(key, value string)
}

// storeDeleter and storeClearer are the optional halves of the contract; a
// store that implements them backs $prefs.removeValueForKey and
// $prefs.removeAllValues as well.
type storeDeleter interface {
	Delete(key string)
}

type storeClearer interface {
	Clear()
}

// ScriptEngine executes Quantumult X rewrite scripts against a request or
// response. Each evaluation gets a fresh goja runtime, so scripts cannot leak
// state across calls; persistent state goes through $persistentStore instead.
type ScriptEngine struct {
	// PersistentStore is an optional key-value store backing
	// $persistentStore.read/write and $prefs. It may be nil, in which case
	// writes are silently dropped and reads return null.
	PersistentStore Store
	// Notify is an optional callback backing $notify and $notification.post.
	Notify func(title, subtitle, body string)
	// HTTPClient is used by $task.fetch. When nil, a client that dials through
	// mihomo's dialer with a 10 second timeout is used.
	HTTPClient *http.Client

	once   sync.Once
	client *http.Client
}

// ScriptResult is what a script produced, returned to the caller so it can
// apply rewrites to the in-flight request or response.
type ScriptResult struct {
	// Done is the object passed to $done({...}), merged with the changes the
	// script made directly on $request or $response, which is how Quantumult X
	// applies edits. It is nil when the script changed nothing.
	Done map[string]interface{}
}

// RunScript evaluates script against the given request and/or response. At
// least one of req/resp must be non-nil. The changes the script asked for, via
// $done or by editing $request/$response in place, are returned so the caller
// can apply them.
func (e *ScriptEngine) RunScript(script string, req *http.Request, resp *http.Response) (*ScriptResult, error) {
	vm := goja.New()

	state, timers, err := e.injectGlobals(vm, req, resp)
	if err != nil {
		return nil, err
	}

	// Run with a hard timeout. goja.Interrupt is checked at JS bytecode
	// boundaries, so an infinite JS loop is still broken out of.
	deadline := time.Now().Add(scriptTimeout)
	interrupt := time.AfterFunc(scriptTimeout, func() {
		vm.Interrupt("mitm script timeout")
	})
	_, err = vm.RunString(script)
	interrupt.Stop()
	if err != nil {
		return nil, fmt.Errorf("mitm: script execution failed: %w", err)
	}

	if err := timers.run(vm, deadline); err != nil {
		return nil, err
	}

	return &ScriptResult{Done: e.collectResult(vm, state, req, resp)}, nil
}

// collectResult reads back $done and folds in the edits the script made on
// $request and $response, which is how Quantumult X scripts usually work.
func (e *ScriptEngine) collectResult(
	vm *goja.Runtime,
	state *scriptState,
	req *http.Request,
	resp *http.Response,
) map[string]interface{} {
	done := collectDone(vm)
	if done == nil {
		done = map[string]interface{}{}
	}
	mergeRequestEdits(done, exportedObject(vm, "$request"), state)
	mergeResponseEdits(done, exportedObject(vm, "$response"), state)
	if len(done) == 0 {
		return nil
	}
	return done
}

// collectDone reads back the value the script passed to $done, if any.
func collectDone(vm *goja.Runtime) map[string]interface{} {
	v := vm.Get("$__done")
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	return exportMap(v)
}

// exportedObject reads a script global back as a plain map.
func exportedObject(vm *goja.Runtime, name string) map[string]interface{} {
	v := vm.Get(name)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	return exportMap(v)
}

func exportMap(v goja.Value) map[string]interface{} {
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

// injectGlobals wires the Quantumult X global API into the runtime and returns
// the state the caller needs to detect edits made in place.
func (e *ScriptEngine) injectGlobals(
	vm *goja.Runtime,
	req *http.Request,
	resp *http.Response,
) (*scriptState, *timerQueue, error) {
	state := &scriptState{}

	reqObj := vm.NewObject()
	if req != nil {
		body, restored := readScriptBody(req.Body)
		req.Body = restored
		state.reqURL = req.URL.String()
		state.reqMethod = req.Method
		state.reqHeaders = headerToMap(req.Header)
		state.reqBody = body
		_ = reqObj.Set("url", state.reqURL)
		_ = reqObj.Set("method", state.reqMethod)
		_ = reqObj.Set("scheme", req.URL.Scheme)
		_ = reqObj.Set("path", req.URL.Path)
		_ = reqObj.Set("headers", headerObject(vm, state.reqHeaders))
		_ = reqObj.Set("body", body)
	}
	_ = vm.Set("$request", reqObj)

	respObj := vm.NewObject()
	if resp != nil {
		body, restored := readScriptBody(resp.Body)
		resp.Body = restored
		state.respStatus = resp.StatusCode
		state.respHeaders = headerToMap(resp.Header)
		state.respBody = body
		// Quantumult X exposes the code as statusCode; older scripts and this
		// package's first version used status, so both are provided.
		_ = respObj.Set("statusCode", resp.StatusCode)
		_ = respObj.Set("status", resp.StatusCode)
		_ = respObj.Set("headers", headerObject(vm, state.respHeaders))
		_ = respObj.Set("body", body)
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

	e.injectStore(vm)
	e.injectNotify(vm)
	e.injectConsole(vm)
	e.injectFetch(vm)

	timers := &timerQueue{}
	_ = vm.Set("setTimeout", func(call goja.FunctionCall) goja.Value {
		delay := int64(0)
		if n, ok := call.Argument(1).Export().(int64); ok {
			delay = n
		}
		callable, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			return goja.Undefined()
		}
		timers.add(time.Duration(delay)*time.Millisecond, callable)
		return goja.Undefined()
	})

	return state, timers, nil
}

// injectStore backs $persistentStore and $prefs, which are two names for the
// same store in Quantumult X.
func (e *ScriptEngine) injectStore(vm *goja.Runtime) {
	store := vm.NewObject()
	_ = store.Set("read", func(call goja.FunctionCall) goja.Value {
		return e.storeValue(vm, call.Argument(0).String())
	})
	_ = store.Set("write", func(call goja.FunctionCall) goja.Value {
		if e.PersistentStore != nil {
			e.PersistentStore.Write(call.Argument(0).String(), call.Argument(1).String())
		}
		return goja.Undefined()
	})
	_ = store.Set("valueForKey", func(call goja.FunctionCall) goja.Value {
		return e.storeValue(vm, call.Argument(0).String())
	})
	// Quantumult X orders the arguments value first, key second.
	_ = store.Set("setValueForKey", func(call goja.FunctionCall) goja.Value {
		if e.PersistentStore != nil {
			e.PersistentStore.Write(call.Argument(1).String(), call.Argument(0).String())
		}
		return goja.Undefined()
	})
	_ = store.Set("removeValueForKey", func(call goja.FunctionCall) goja.Value {
		if deleter, ok := e.PersistentStore.(storeDeleter); ok {
			deleter.Delete(call.Argument(0).String())
		}
		return goja.Undefined()
	})
	_ = store.Set("removeAllValues", func(call goja.FunctionCall) goja.Value {
		if clearer, ok := e.PersistentStore.(storeClearer); ok {
			clearer.Clear()
		}
		return goja.Undefined()
	})
	_ = vm.Set("$persistentStore", store)
	_ = vm.Set("$prefs", store)
}

func (e *ScriptEngine) storeValue(vm *goja.Runtime, key string) goja.Value {
	if e.PersistentStore == nil {
		return goja.Null()
	}
	if v, ok := e.PersistentStore.Read(key); ok {
		return vm.ToValue(v)
	}
	return goja.Null()
}

// injectNotify backs $notify(title, subtitle, body) and
// $notification.post(title, subtitle, body).
func (e *ScriptEngine) injectNotify(vm *goja.Runtime) {
	post := func(call goja.FunctionCall) goja.Value {
		if e.Notify != nil {
			e.Notify(call.Argument(0).String(), call.Argument(1).String(), call.Argument(2).String())
		}
		return goja.Undefined()
	}
	notification := vm.NewObject()
	_ = notification.Set("post", post)
	_ = vm.Set("$notification", notification)
	_ = vm.Set("$notify", post)
}

// injectConsole routes console output to the core log instead of dropping it,
// so a script can be debugged from the app's log view.
func (e *ScriptEngine) injectConsole(vm *goja.Runtime) {
	write := func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, arg := range call.Arguments {
			parts = append(parts, strings.TrimSpace(arg.String()))
		}
		log.Infoln("[MITM] script: %s", strings.Join(parts, " "))
		return goja.Undefined()
	}
	console := vm.NewObject()
	for _, name := range []string{"log", "info", "warn", "error", "debug"} {
		_ = console.Set(name, write)
	}
	_ = vm.Set("console", console)
}

// injectFetch backs $task.fetch(request), which Quantumult X resolves with an
// object holding statusCode, headers and body. The request is performed
// synchronously and returned as an already-resolved promise, so the script's
// .then handler runs within the same evaluation.
func (e *ScriptEngine) injectFetch(vm *goja.Runtime) {
	task := vm.NewObject()
	_ = task.Set("fetch", func(call goja.FunctionCall) goja.Value {
		return e.fetch(vm, call.Argument(0))
	})
	_ = vm.Set("$task", task)
}

func (e *ScriptEngine) fetch(vm *goja.Runtime, options goja.Value) goja.Value {
	promise, resolve, reject := vm.NewPromise()

	spec := options.Export()
	fields, _ := spec.(map[string]interface{})
	url := toString(fields["url"])
	if url == "" {
		_ = reject(vm.NewGoError(fmt.Errorf("mitm: $task.fetch needs a url")))
		return vm.ToValue(promise)
	}

	method := strings.ToUpper(toString(fields["method"]))
	if method == "" {
		method = http.MethodGet
	}
	timeout := scriptFetchTimeout
	if seconds, ok := toInt(fields["timeout"]); ok && seconds > 0 {
		timeout = time.Duration(seconds) * time.Second
	}

	body := toString(fields["body"])
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		_ = reject(vm.NewGoError(err))
		return vm.ToValue(promise)
	}
	if headers, ok := fields["headers"].(map[string]interface{}); ok {
		for name, value := range headers {
			req.Header.Set(name, toString(value))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := e.httpClient().Do(req.WithContext(ctx))
	if err != nil {
		_ = reject(vm.NewGoError(err))
		return vm.ToValue(promise)
	}
	defer resp.Body.Close()

	payload, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRewriteBody))
	if readErr != nil {
		_ = reject(vm.NewGoError(readErr))
		return vm.ToValue(promise)
	}

	result := vm.NewObject()
	_ = result.Set("statusCode", resp.StatusCode)
	_ = result.Set("headers", headerToMap(resp.Header))
	_ = result.Set("body", string(payload))
	_ = resolve(result)
	return vm.ToValue(promise)
}

func (e *ScriptEngine) httpClient() *http.Client {
	e.once.Do(func() {
		if e.HTTPClient != nil {
			e.client = e.HTTPClient
			return
		}
		e.client = &http.Client{
			Timeout: scriptFetchTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        4,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}
	})
	return e.client
}

// scriptState is what $request and $response looked like before the script ran,
// so edits made in place can be told apart from untouched values.
type scriptState struct {
	reqURL      string
	reqMethod   string
	reqBody     string
	reqHeaders  map[string]string
	respStatus  int
	respBody    string
	respHeaders map[string]string
}

// mergeRequestEdits folds in-place edits of $request into the $done object.
func mergeRequestEdits(done, edited map[string]interface{}, state *scriptState) {
	if edited == nil || state == nil || state.reqURL == "" {
		return
	}
	if url := toString(edited["url"]); url != "" && url != state.reqURL {
		setIfAbsent(done, "url", url)
	}
	if body := toString(edited["body"]); body != state.reqBody {
		setIfAbsent(done, "body", body)
	}
	mergeHeaderEdits(done, edited["headers"], state.reqHeaders)
}

// mergeResponseEdits folds in-place edits of $response into the $done object.
func mergeResponseEdits(done, edited map[string]interface{}, state *scriptState) {
	if edited == nil || state == nil || (state.respBody == "" && state.respStatus == 0) {
		return
	}
	if status, ok := statusFrom(edited["statusCode"]); ok && status != state.respStatus {
		setIfAbsent(done, "status", status)
	}
	if body := toString(edited["body"]); body != state.respBody {
		setIfAbsent(done, "body", body)
	}
	mergeHeaderEdits(done, edited["headers"], state.respHeaders)
}

func mergeHeaderEdits(done map[string]interface{}, edited interface{}, before map[string]string) {
	current, ok := edited.(map[string]interface{})
	if !ok {
		return
	}
	changes := map[string]interface{}{}
	for name, value := range current {
		text := toString(value)
		if before[name] != text {
			changes[name] = text
		}
	}
	// A header the script deleted disappears from the object, so removals have
	// to be found by looking for what used to be there.
	for name := range before {
		if _, kept := current[name]; !kept {
			changes[name] = "-"
		}
	}
	if len(changes) == 0 {
		return
	}
	if existing, ok := done["headers"]; ok {
		if merged, ok := existing.(map[string]interface{}); ok {
			for name, value := range merged {
				changes[name] = value
			}
		}
	}
	done["headers"] = changes
}

func setIfAbsent(done map[string]interface{}, key string, value interface{}) {
	if _, present := done[key]; !present {
		done[key] = value
	}
}

// timerQueue holds the callbacks a script scheduled with setTimeout. They run
// after the main body finishes, which is what the common
// "setTimeout(() => $done({...}), 100)" pattern expects, without letting a
// script sleep the tunnel goroutine for an arbitrary time.
type timerQueue struct {
	entries []timerEntry
}

type timerEntry struct {
	delay    time.Duration
	callable goja.Callable
}

func (q *timerQueue) add(delay time.Duration, callable goja.Callable) {
	q.entries = append(q.entries, timerEntry{delay: delay, callable: callable})
}

func (q *timerQueue) run(vm *goja.Runtime, deadline time.Time) error {
	for _, entry := range q.entries {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("mitm: script timeout")
		}
		if entry.delay > 0 {
			wait := entry.delay
			if wait > remaining {
				wait = remaining
			}
			time.Sleep(wait)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("mitm: script timeout")
		}
		if _, err := entry.callable(goja.Undefined()); err != nil {
			return fmt.Errorf("mitm: script timer failed: %w", err)
		}
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

// headerObject builds a plain JavaScript object from a header map. A script has
// to be able to add, change and delete entries, so the map is copied into the
// runtime rather than wrapped.
func headerObject(vm *goja.Runtime, headers map[string]string) *goja.Object {
	object := vm.NewObject()
	for name, value := range headers {
		_ = object.Set(name, value)
	}
	return object
}

// readScriptBody reads a body for a script and hands back a replacement reader,
// so exposing the body to JavaScript does not consume the stream. A body too
// large to hand over is put back in front of the stream untouched.
func readScriptBody(body io.ReadCloser) (string, io.ReadCloser) {
	data, restored, ok := bufferBody(body)
	if !ok {
		return "", restored
	}
	return string(data), restored
}

// bodyCloser returns a new body closer for the given string, used when a
// script rewrites the request or response body.
func bodyCloser(s string) io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte(s)))
}
