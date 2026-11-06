package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// watchedFlag notes the name of a flag whose value doesn't parse, so the error
// can name the flag without repeating the value.
type watchedFlag struct {
	flag.Value
	name   string
	failed *string
}

func (w *watchedFlag) Set(s string) error {
	if err := w.Value.Set(s); err != nil {
		*w.failed = w.name
		return err
	}
	return nil
}

func (w *watchedFlag) IsBoolFlag() bool {
	b, ok := w.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// parseQuiet parses a command's flags. Go's flag package would print errors that
// quote what was typed, which may be a key or a DSN with its password, typed in
// the wrong place. So it prints nothing, and parseQuiet names the flag, or the
// argument's position, instead. command is what follows "prodmask", such as scan
// or leak-check hash, and usage is the help above the flags. It returns false,
// with the exit status, when the command should stop.
func parseQuiet(env *Env, command string, fs *flag.FlagSet, usage string, args []string) (bool, int) {
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var failed string
	var originals []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) {
		originals = append(originals, &flag.Flag{Name: f.Name, Value: f.Value})
		f.Value = &watchedFlag{Value: f.Value, name: f.Name, failed: &failed}
	})
	err := fs.Parse(args)
	for _, o := range originals {
		fs.Lookup(o.Name).Value = o.Value
	}
	switch {
	case err == nil:
		if fs.NArg() > 0 {
			fmt.Fprintf(env.Stderr, "prodmask %s: argument %d is unexpected: it takes flags only; it isn't shown, in case it is a secret\n",
				command, len(args)-fs.NArg()+1)
			return false, ExitUsage
		}
		return true, ExitOK
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(env.Stderr, usage, "\nFlags:\n")
		fs.SetOutput(env.Stderr)
		fs.PrintDefaults()
		return false, ExitOK
	case failed != "":
		fmt.Fprintf(env.Stderr, "prodmask %s: the value of --%s isn't valid; it isn't shown, in case it is a secret\n", command, failed)
	case strings.HasPrefix(err.Error(), "flag needs an argument: "):
		name := strings.TrimLeft(strings.TrimPrefix(err.Error(), "flag needs an argument: "), "-")
		if f := fs.Lookup(name); f != nil {
			fmt.Fprintf(env.Stderr, "prodmask %s: --%s needs a value\n", command, f.Name)
		} else {
			fmt.Fprintf(env.Stderr, "prodmask %s: a flag needs a value\n", command)
		}
	default:
		fmt.Fprintf(env.Stderr, "prodmask %s: argument %d is no flag it knows; it isn't shown, in case it is a secret\n", command, badFlagAt(fs, args))
	}
	fmt.Fprintf(env.Stderr, "Run \"prodmask %s -h\" for its flags.\n", command)
	return false, ExitUsage
}

// badFlagAt returns the position, from 1, of the first argument that is no
// flag fs knows, reading arguments as the flag package does.
func badFlagAt(fs *flag.FlagSet, args []string) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			break
		}
		name := a[1:]
		if name[0] == '-' {
			name = name[1:]
		}
		if name == "" || name[0] == '-' || name[0] == '=' {
			return i + 1
		}
		name, _, hasValue := strings.Cut(name, "=")
		f := fs.Lookup(name)
		if f == nil {
			return i + 1
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !hasValue && !(ok && b.IsBoolFlag()) {
			i++
		}
	}
	return 1
}
