// Package mcpclient checks prodmask mcp against the official Model Context
// Protocol Go SDK's client: it builds the binary, starts it over standard
// input and output, and calls each tool against a test server. It's a
// module of its own, so the SDK never reaches prodmask's go.mod.
package mcpclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

const db = "prodmask_fixture_mcpclient"

func TestSDKClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg, err := mysql.ParseDSN(testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = ""
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()
	b := make([]byte, 12)
	rand.Read(b)
	password := "Pm1-" + hex.EncodeToString(b)
	for _, q := range []string{
		"DROP DATABASE IF EXISTS " + db,
		"CREATE DATABASE " + db,
		"CREATE TABLE " + db + ".customers (id INT PRIMARY KEY, email VARCHAR(80))",
		"INSERT INTO " + db + ".customers VALUES (1, 'ada@example.com')",
		"DROP USER IF EXISTS 'pm_sdk_reader'@'%'",
		"CREATE USER 'pm_sdk_reader'@'%' IDENTIFIED BY '" + password + "'",
		"GRANT SELECT, SHOW VIEW ON " + db + ".* TO 'pm_sdk_reader'@'%'",
	} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			q, _, _ = strings.Cut(q, " IDENTIFIED")
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+db)
	defer admin.ExecContext(context.Background(), "DROP USER IF EXISTS 'pm_sdk_reader'@'%'")

	bin := filepath.Join(t.TempDir(), "prodmask")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/prodmask")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building prodmask: %v\n%s", err, out)
	}

	reader := cfg.Clone()
	reader.User, reader.Passwd, reader.DBName = "pm_sdk_reader", password, db
	cmd := exec.Command(bin, "mcp")
	// The DSN goes through the environment, so the password isn't in the
	// process's arguments.
	cmd.Env = append(os.Environ(), "PRODMASK_DSN="+reader.FormatDSN(), "PRODMASK_PASSWORD=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "prodmask-mcpclient-test", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting: %v\n%s", err, stderr.String())
	}
	// The SDK asks for the newest protocol through server/discover first,
	// and falls back to initialize, where the server speaks 2025-11-25.
	if v := session.InitializeResult().ProtocolVersion; v != "2025-11-25" {
		t.Errorf("negotiated protocol %q, want 2025-11-25", v)
	}

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s isn't marked read-only: %+v", tool.Name, tool.Annotations)
		}
		if tool.Name == "query" && (tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint) {
			t.Errorf("query's openWorldHint isn't true")
		}
	}
	slices.Sort(names)
	if strings.Join(names, " ") != "about describe_table list_tables query" {
		t.Errorf("tools: %v", names)
	}

	call := func(name string, args map[string]any) (string, bool) {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(res.Content) != 1 {
			t.Fatalf("%s: %d contents", name, len(res.Content))
		}
		text, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("%s: content of type %T", name, res.Content[0])
		}
		return text.Text, res.IsError
	}
	if text, isErr := call("about", nil); isErr || !strings.Contains(text, `"serving": true`) {
		t.Errorf("about: %s", text)
	}
	if text, isErr := call("list_tables", nil); isErr || !strings.Contains(text, `"name": "customers"`) {
		t.Errorf("list_tables: %s", text)
	}
	if text, isErr := call("describe_table", map[string]any{"table": "customers"}); isErr || !strings.Contains(text, `"name": "email"`) {
		t.Errorf("describe_table: %s", text)
	}
	if text, isErr := call("query", map[string]any{"sql": "SELECT COUNT(*) FROM customers"}); isErr || !strings.Contains(text, `"rows"`) {
		t.Errorf("query: %s", text)
	}
	if text, isErr := call("query", map[string]any{"sql": "SELECT SLEEP(1)"}); !isErr || !strings.Contains(text, "refused") {
		t.Errorf("a refused statement: %s", text)
	}

	if err := session.Close(); err != nil {
		t.Errorf("closing: %v", err)
	}
	log := stderr.String()
	if !strings.Contains(log, "about: answered") || strings.Contains(log, password) || strings.Contains(log, cfg.Addr) {
		t.Errorf("standard error:\n%s", log)
	}
}
