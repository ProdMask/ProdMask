package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// testWire is a Wire with two tools: echo answers its text argument, and
// wait waits until its call is cancelled.
func testWire() *Wire {
	return &Wire{
		Name: "prodmask", Version: "1.2.3", Instructions: "call about first",
		Tools: []ToolDef{{Name: "echo", Description: "echoes", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		Call: func(ctx context.Context, name string, args map[string]json.RawMessage) (ToolResult, error) {
			switch name {
			case "echo":
				var text string
				if json.Unmarshal(args["text"], &text) != nil {
					return ToolResult{}, InvalidParamsError{"echo needs text"}
				}
				return ToolResult{Text: text}, nil
			case "wait":
				<-ctx.Done()
				return ToolResult{}, ctx.Err()
			}
			return ToolResult{}, InvalidParamsError{"no tool of that name"}
		},
	}
}

// transcript serves the input lines and returns the output lines.
func transcript(t *testing.T, lines ...string) []string {
	t.Helper()
	var out bytes.Buffer
	if err := testWire().Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(got) == 1 && got[0] == "" {
		return nil
	}
	return got
}

// message decodes one output line.
func message(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("an output line isn't JSON: %q", line)
	}
	if m["jsonrpc"] != "2.0" {
		t.Errorf("no jsonrpc 2.0 in %q", line)
	}
	return m
}

func errorCode(m map[string]any) float64 {
	e, _ := m["error"].(map[string]any)
	code, _ := e["code"].(float64)
	return code
}

func TestWireInitialize(t *testing.T) {
	for _, asked := range append(protocolVersions, "1999-01-01") {
		out := transcript(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+asked+`","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		if len(out) != 1 {
			t.Fatalf("%s: %d lines, want 1 (the notification has no answer): %q", asked, len(out), out)
		}
		res, _ := message(t, out[0])["result"].(map[string]any)
		want := asked
		if asked == "1999-01-01" {
			want = "2025-11-25"
		}
		info, _ := res["serverInfo"].(map[string]any)
		caps, _ := res["capabilities"].(map[string]any)
		if res["protocolVersion"] != want || info["name"] != "prodmask" || info["version"] != "1.2.3" ||
			caps["tools"] == nil || res["instructions"] != "call about first" {
			t.Errorf("%s: %v", asked, res)
		}
	}
}

func TestWireMethods(t *testing.T) {
	out := transcript(t,
		`{"jsonrpc":"2.0","id":"a","method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nothing"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":6,"Method":"ping"}`,
		`{"jsonrpc":"2.0","ID":7,"method":"ping"}`,
		`{"jsonrpc":"1.0","id":8,"method":"ping"}`,
		`{not json`,
		`{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/whatever"}`,
	)
	byID := map[string]map[string]any{}
	var nulls []map[string]any
	for _, line := range out {
		m := message(t, line)
		if m["id"] == nil {
			nulls = append(nulls, m)
			continue
		}
		key, _ := json.Marshal(m["id"])
		byID[string(key)] = m
	}
	if r, _ := byID[`"a"`]["result"].(map[string]any); r == nil || len(r) != 0 {
		t.Errorf("ping: %v", byID[`"a"`])
	}
	tools, _ := byID["2"]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Errorf("tools/list: %v", byID["2"])
	}
	content, _ := byID["3"]["result"].(map[string]any)["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "hi" || byID["3"]["result"].(map[string]any)["isError"] != false {
		t.Errorf("tools/call: %v", byID["3"])
	}
	for id, code := range map[string]float64{"4": codeInvalidParams, "5": codeMethodNotFound, "6": codeInvalidRequest, "8": codeInvalidRequest} {
		if errorCode(byID[id]) != code {
			t.Errorf("request %s: %v, want error %v", id, byID[id], code)
		}
	}
	// "ID" isn't "id": that line is a notification of ping, with no answer.
	if _, ok := byID["7"]; ok {
		t.Errorf("an ID member was read as id: %v", byID["7"])
	}
	codes := map[float64]int{}
	for _, m := range nulls {
		codes[errorCode(m)]++
	}
	if codes[codeParse] != 1 || codes[codeInvalidRequest] != 1 || len(nulls) != 2 {
		t.Errorf("answers with a null id: %v", nulls)
	}
}

func TestWireBatch(t *testing.T) {
	out := transcript(t, `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},`+
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}]`, `[]`)
	if len(out) != 2 {
		t.Fatalf("%d lines: %q", len(out), out)
	}
	// The batch's answer waits for its tool call, so it may come second.
	array, single := out[0], out[1]
	if strings.HasPrefix(single, "[") {
		array, single = single, array
	}
	var batch []map[string]any
	if err := json.Unmarshal([]byte(array), &batch); err != nil || len(batch) != 2 {
		t.Fatalf("the batch's answer: %q", array)
	}
	if errorCode(message(t, single)) != codeInvalidRequest {
		t.Errorf("an empty batch: %q", single)
	}
}

func TestWireCancel(t *testing.T) {
	out := transcript(t,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"wait"}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9,"reason":"user"}}`,
		`{"jsonrpc":"2.0","id":10,"method":"ping"}`)
	if len(out) != 1 || message(t, out[0])["id"] != float64(10) {
		t.Fatalf("a cancelled call was answered, or the ping wasn't: %q", out)
	}
}

// TestWireContext: when Serve's context ends, it returns though its input
// stays open, and a running call's answer is dropped.
func TestWireContext(t *testing.T) {
	in, client := io.Pipe()
	defer client.Close()
	answers, server := io.Pipe()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(answers)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testWire().Serve(ctx, in, server) }()
	io.WriteString(client, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait"}}`+"\n")
	io.WriteString(client, `{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
	if m := message(t, <-lines); m["id"] != float64(2) {
		t.Fatalf("the ping's answer: %v", m)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve didn't return when its context ended")
	}
	server.Close()
	for l := range lines {
		t.Errorf("an answer after the context ended: %q", l)
	}
}

func TestWireLines(t *testing.T) {
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	// Exactly 4 MiB, and one byte over.
	under := strings.TrimSuffix(ping, "}") + strings.Repeat(" ", maxLine-len(ping)) + "}"
	over := under + " "
	out := transcript(t, under, over, `{"jsonrpc":"2.0","id":3,"method":"ping"}`+"\r", `{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	if len(out) != 4 {
		t.Fatalf("%d lines, want 4", len(out))
	}
	if m := message(t, out[0]); m["id"] != float64(1) || m["result"] == nil {
		t.Errorf("a 4 MiB line: %v", m)
	}
	if m := message(t, out[1]); m["id"] != nil || errorCode(m) != codeParse {
		t.Errorf("a line over 4 MiB: %v", m)
	}
	if m := message(t, out[2]); m["id"] != float64(3) || m["result"] == nil {
		t.Errorf("a line ending in CR: %v", m)
	}
	if m := message(t, out[3]); m["id"] != float64(4) {
		t.Errorf("the last line, with no newline: %v", m)
	}
}
