package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sync"
)

// protocolVersions are the Model Context Protocol versions the server
// speaks, oldest first. A client asking for another gets the newest.
var protocolVersions = []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}

// maxLine is the longest message line read; a longer one is answered with a
// parse error and skipped.
const maxLine = 4 << 20

// JSON-RPC 2.0 error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// ToolDef is a tool as tools/list describes it.
type ToolDef struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations ToolAnnotations `json:"annotations"`
}

// ToolAnnotations are a tool's hints to the client.
type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

// ToolResult is a tool's answer: JSON text, or an error's words.
type ToolResult struct {
	Text    string
	IsError bool
}

// InvalidParamsError makes a tool call's answer a JSON-RPC invalid-params
// error, as for an unknown tool or a missing argument.
type InvalidParamsError struct{ Message string }

func (e InvalidParamsError) Error() string { return e.Message }

// Wire is the protocol's side of the server: newline-delimited JSON-RPC 2.0
// messages, the tools-only subset of the Model Context Protocol.
type Wire struct {
	Name, Version, Instructions string
	Tools                       []ToolDef
	// Call runs a tool. ctx ends when the client cancels the request.
	Call func(ctx context.Context, name string, args map[string]json.RawMessage) (ToolResult, error)

	outMu sync.Mutex
	out   io.Writer

	mu      sync.Mutex
	running map[string]*call // tools/call requests running, by id
	wg      sync.WaitGroup
}

type call struct {
	cancel    context.CancelFunc
	cancelled bool
}

// Serve reads messages from in and writes answers to out until in ends. It
// then waits for the calls still running, which the runner's deadline
// bounds, writes their answers and returns nil, or the read's error when in
// fails other than by ending. When ctx ends, the calls
// are cancelled, their answers dropped, and Serve returns nil without
// waiting for in: a read from a terminal or a pipe isn't cut short.
func (w *Wire) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	w.out = out
	w.running = map[string]*call{}
	type read struct {
		line    []byte
		tooLong bool
		err     error
	}
	reads := make(chan read)
	go func() {
		r := bufio.NewReaderSize(in, 64<<10)
		for {
			line, tooLong, err := readLine(r)
			select {
			case reads <- read{line, tooLong, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		var got read
		select {
		case got = <-reads:
		case <-ctx.Done():
			w.wg.Wait()
			return nil
		}
		if got.tooLong {
			w.write(errorMessage(nil, codeParse, "the message is longer than 4 MiB"))
			continue
		}
		if got.err != nil {
			w.wg.Wait()
			if errors.Is(got.err, io.EOF) {
				return nil
			}
			return got.err
		}
		w.handleLine(ctx, got.line)
	}
}

// readLine reads a line without its newline and a carriage return before
// it. A line over maxLine is skipped to its newline and reported.
func readLine(r *bufio.Reader) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxLine+2 {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !(errors.Is(err, io.EOF) && (len(buf) > 0 || tooLong)) {
			return nil, false, err
		}
		buf = bytes.TrimSuffix(bytes.TrimSuffix(buf, []byte("\n")), []byte("\r"))
		if tooLong || len(buf) > maxLine {
			return nil, true, nil
		}
		return buf, false, nil
	}
}

func (w *Wire) handleLine(ctx context.Context, line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	if line[0] != '[' {
		w.dispatch(ctx, line, w.write)
		return
	}
	var items []json.RawMessage
	if err := json.Unmarshal(line, &items); err != nil {
		w.write(errorMessage(nil, codeParse, "the message isn't JSON"))
		return
	}
	if len(items) == 0 {
		w.write(errorMessage(nil, codeInvalidRequest, "the batch is empty"))
		return
	}
	// A batch is answered as one array, once each request in it is.
	answers := make([][]byte, len(items))
	var pending sync.WaitGroup
	for i, item := range items {
		pending.Add(1)
		if !w.dispatch(ctx, item, func(msg []byte) { answers[i] = msg; pending.Done() }) {
			pending.Done()
		}
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		pending.Wait()
		var out [][]byte
		for _, a := range answers {
			if a != nil {
				out = append(out, a)
			}
		}
		if len(out) > 0 {
			w.write(slices.Concat([]byte("["), bytes.Join(out, []byte(",")), []byte("]")))
		}
	}()
}

// dispatch handles one message. A request's reply is called exactly once,
// perhaps later, with nil when there's no answer to send (a cancelled
// call); a notification's never, and dispatch then returns false.
func (w *Wire) dispatch(ctx context.Context, raw []byte, reply func([]byte)) bool {
	// Members are read by their exact names: encoding/json would take
	// "Method" for "method".
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		var probe any
		if json.Unmarshal(raw, &probe) != nil {
			reply(errorMessage(nil, codeParse, "the message isn't JSON"))
		} else {
			reply(errorMessage(nil, codeInvalidRequest, "the message isn't a JSON-RPC request"))
		}
		return true
	}
	id, hasID := m["id"]
	if hasID && !validID(id) {
		reply(errorMessage(nil, codeInvalidRequest, "the request's id isn't a string or a number"))
		return true
	}
	var method, version string
	_, isResponse := m["result"]
	_, isError := m["error"]
	methodRaw, hasMethod := m["method"]
	if !hasMethod && (isResponse || isError) {
		return false // an answer to a request the server never sends
	}
	if json.Unmarshal(m["jsonrpc"], &version) != nil || version != "2.0" || !hasMethod || json.Unmarshal(methodRaw, &method) != nil {
		if !hasID {
			id = nil
		}
		reply(errorMessage(id, codeInvalidRequest, "the message isn't a JSON-RPC 2.0 request"))
		return true
	}
	var params map[string]json.RawMessage
	if p, ok := m["params"]; ok && string(p) != "null" {
		if err := json.Unmarshal(p, &params); err != nil {
			if hasID {
				reply(errorMessage(id, codeInvalidParams, "params isn't an object"))
				return true
			}
			return false
		}
	}
	if !hasID {
		if method == "notifications/cancelled" {
			w.cancel(params["requestId"])
		}
		return false
	}
	switch method {
	case "initialize":
		reply(resultMessage(id, w.initialize(params)))
	case "ping":
		reply(resultMessage(id, struct{}{}))
	case "tools/list":
		reply(resultMessage(id, map[string]any{"tools": w.Tools}))
	case "tools/call":
		w.toolsCall(ctx, id, params, reply)
	default:
		reply(errorMessage(id, codeMethodNotFound, "no method of that name"))
	}
	return true
}

// validID reports whether a request id is a string or a number.
func validID(id json.RawMessage) bool {
	var v any
	if json.Unmarshal(id, &v) != nil {
		return false
	}
	switch v.(type) {
	case string, float64:
		return true
	}
	return false
}

func (w *Wire) initialize(params map[string]json.RawMessage) map[string]any {
	version := protocolVersions[len(protocolVersions)-1]
	var asked string
	if json.Unmarshal(params["protocolVersion"], &asked) == nil && slices.Contains(protocolVersions, asked) {
		version = asked
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": w.Name, "version": w.Version},
		"instructions":    w.Instructions,
	}
}

// toolsCall runs a tool in its own goroutine, so the reader goes on reading
// and sees a cancellation; a cancelled call's answer isn't sent.
func (w *Wire) toolsCall(ctx context.Context, id json.RawMessage, params map[string]json.RawMessage, reply func([]byte)) {
	var name string
	if json.Unmarshal(params["name"], &name) != nil || name == "" {
		reply(errorMessage(id, codeInvalidParams, "tools/call needs a tool's name"))
		return
	}
	var args map[string]json.RawMessage
	if a, ok := params["arguments"]; ok && string(a) != "null" {
		if json.Unmarshal(a, &args) != nil {
			reply(errorMessage(id, codeInvalidParams, "arguments isn't an object"))
			return
		}
	}
	key := idKey(id)
	callCtx, cancel := context.WithCancel(ctx)
	c := &call{cancel: cancel}
	w.mu.Lock()
	w.running[key] = c
	w.mu.Unlock()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer cancel()
		res, err := w.Call(callCtx, name, args)
		w.mu.Lock()
		cancelled := c.cancelled || ctx.Err() != nil
		if w.running[key] == c {
			delete(w.running, key)
		}
		w.mu.Unlock()
		var invalid InvalidParamsError
		switch {
		case cancelled:
			reply(nil)
		case errors.As(err, &invalid):
			reply(errorMessage(id, codeInvalidParams, invalid.Message))
		case err != nil:
			reply(resultMessage(id, toolContent(err.Error(), true)))
		default:
			reply(resultMessage(id, toolContent(res.Text, res.IsError)))
		}
	}()
}

func toolContent(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isError}
}

// cancel cancels a running tools/call by its request id.
func (w *Wire) cancel(requestID json.RawMessage) {
	if requestID == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if c := w.running[idKey(requestID)]; c != nil {
		c.cancelled = true
		c.cancel()
	}
}

// idKey is a request id's key: its JSON value, compacted.
func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		return string(id)
	}
	return b.String()
}

func resultMessage(id json.RawMessage, result any) []byte {
	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if err != nil {
		return errorMessage(id, codeInternal, "the answer couldn't be written")
	}
	return msg
}

func errorMessage(id json.RawMessage, code int, message string) []byte {
	if id == nil {
		id = json.RawMessage("null")
	}
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": message}})
	return msg
}

// write writes one message line; nil writes nothing.
func (w *Wire) write(msg []byte) {
	if msg == nil {
		return
	}
	w.outMu.Lock()
	defer w.outMu.Unlock()
	w.out.Write(append(msg, '\n'))
}
