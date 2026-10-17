// Package cli is the prodmask command line. The free build's commands live
// here behind a small registry, so another build can add commands of its own
// and keep the same flags, output and exit statuses for the free ones.
package cli

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strings"
	"unicode/utf8"
)

// Exit statuses. Every build shares them, so a status means the same thing
// whichever command returns it.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitFindings = 3
	ExitLicence  = 4 // a command that needs a prodmask Pro licence found no valid one
)

// Command is one prodmask command, such as scan.
type Command struct {
	Name    string   // the word that selects it: prodmask <Name>
	Aliases []string // other words that select it, such as --version; not listed
	Args    string   // what follows the name in the command list, such as "[flags]"
	Summary string   // its line in the command list

	// Run runs the command with the arguments after its name and returns
	// the exit status.
	Run func(ctx context.Context, env *Env, args []string) int
}

// Env is what a command runs with.
type Env struct {
	App    *App
	Stdout io.Writer
	Stderr io.Writer
}

// App is one build of prodmask: its version, the text around its command
// list, and its commands.
type App struct {
	Version string // shown by prodmask version and recorded in reports
	Edition string // the build's name after "prodmask", such as "Pro"; empty for the free build
	About   string // the paragraph above the command list
	Footer  string // the text below the command list

	commands []*Command
}

const freeAbout = `prodmask finds what a plain copy of a MySQL or MariaDB database would carry
into staging: personal data, secrets, and settings that would email or charge
real customers. It only reads, and it never prints the data it samples.
`

const freeFooter = `Run "prodmask scan -h" for the scan flags.
`

// New returns the free build of prodmask.
func New(version string) *App {
	a := &App{Version: version, About: freeAbout, Footer: freeFooter}
	a.Register(FreeCommands()...)
	return a
}

// FreeCommands returns new copies of the free build's commands, for builds
// that add their own.
func FreeCommands() []*Command {
	return []*Command{scanCommand(), versionCommand()}
}

// reserved words select the usage text and can't name a command.
var reserved = []string{"help", "-h", "--help"}

// Register adds commands. It panics if a command has no name or Run
// function, or if a name or alias is already taken, as these are mistakes
// in the program rather than in its input.
func (a *App) Register(cmds ...*Command) {
	for _, c := range cmds {
		if c == nil || c.Name == "" || c.Run == nil {
			panic("cli: a command needs a name and a Run function")
		}
		words := append([]string{c.Name}, c.Aliases...)
		for i, w := range words {
			if w == "" || slices.Contains(reserved, w) || slices.Contains(words[:i], w) || a.Lookup(w) != nil {
				panic(fmt.Sprintf("cli: %q is empty or already taken", w))
			}
		}
		a.commands = append(a.commands, c)
	}
}

// Commands returns the registered commands in name order.
func (a *App) Commands() []*Command {
	cmds := slices.Clone(a.commands)
	slices.SortFunc(cmds, func(x, y *Command) int { return strings.Compare(x.Name, y.Name) })
	return cmds
}

// Lookup returns the command a word selects, or nil.
func (a *App) Lookup(word string) *Command {
	for _, c := range a.commands {
		if c.Name == word || slices.Contains(c.Aliases, word) {
			return c
		}
	}
	return nil
}

// VersionLine is what prodmask version prints, such as "prodmask 0.1.0".
func (a *App) VersionLine() string {
	if a.Edition != "" {
		return "prodmask " + a.Edition + " " + a.Version
	}
	return "prodmask " + a.Version
}

// Usage returns the help text: the about paragraph, the commands in name
// order, and the footer.
func (a *App) Usage() string {
	cmds := a.Commands()
	synopsis := func(c *Command) string {
		return strings.TrimSpace("prodmask " + c.Name + " " + c.Args)
	}
	width := 0
	for _, c := range cmds {
		width = max(width, utf8.RuneCountInString(synopsis(c)))
	}
	var b strings.Builder
	b.WriteString(a.About)
	b.WriteString("\nUsage:\n")
	for _, c := range cmds {
		fmt.Fprintf(&b, "  %-*s    %s\n", width, synopsis(c), c.Summary)
	}
	if a.Footer != "" {
		b.WriteString("\n" + a.Footer)
	}
	return b.String()
}

// Run runs the command that args select and returns the exit status.
func (a *App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, a.Usage())
		return ExitUsage
	}
	if slices.Contains(reserved, args[0]) {
		fmt.Fprint(stdout, a.Usage())
		return ExitOK
	}
	if c := a.Lookup(args[0]); c != nil {
		return c.Run(ctx, &Env{App: a, Stdout: stdout, Stderr: stderr}, args[1:])
	}
	fmt.Fprintf(stderr, "prodmask: unknown command %q\n\n%s", args[0], a.Usage())
	return ExitUsage
}

// BuildVersion returns the version a build reports: stamped when the build
// set it with -ldflags "-X main.version=...", otherwise the module version Go
// recorded for go install or go build, otherwise "dev".
func BuildVersion(stamped string) string {
	if stamped != "" {
		return stamped
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "dev"
}

func versionCommand() *Command {
	return &Command{
		Name:    "version",
		Aliases: []string{"--version"},
		Summary: "print the version",
		Run: func(_ context.Context, env *Env, _ []string) int {
			fmt.Fprintln(env.Stdout, env.App.VersionLine())
			return ExitOK
		},
	}
}
