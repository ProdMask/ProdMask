package harden

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// TestProcess starts this test binary again as a child that calls Process,
// reports its dumpable flag, and waits. The flag reads 0, and this process,
// running as the same user, can't read the child's environment through
// /proc: the kernel makes a non-dumpable process's files root's.
func TestProcess(t *testing.T) {
	if os.Getenv("PRODMASK_HARDEN_CHILD") == "1" {
		Process()
		const prGetDumpable = 3
		dumpable, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
		fmt.Printf("dumpable=%d\n", dumpable)
		io.ReadAll(os.Stdin) // until the parent has looked
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcess$")
	cmd.Env = append(os.Environ(), "PRODMASK_HARDEN_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer stdin.Close()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("the child said nothing: %v", err)
	}
	if got := strings.TrimSpace(line); got != "dumpable=0" {
		t.Errorf("the child read %s after Process, want dumpable=0", got)
	}
	if os.Geteuid() == 0 {
		t.Log("running as root, which reads any process's environment; that half is skipped")
		return
	}
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", cmd.Process.Pid)); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("the child's environment was readable by the same user (%v)", err)
	}
}
