package projectdb

import "io/fs"

// Hint is the line a scan with no DSN adds when the current folder holds one
// configuration Read would read: "this folder has wp-config.php: pass
// --project . to read it". It looks only through stat, at the fixed names,
// so it opens no file. With none, or more than one, it returns "".
func Hint(stat func(name string) (fs.FileInfo, error)) string {
	found := configs(func(name string) bool {
		_, err := stat(name)
		return err == nil
	})
	if len(found) != 1 {
		return ""
	}
	return "this folder has " + found[0] + ": pass --project . to read it"
}
