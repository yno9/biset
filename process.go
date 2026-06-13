package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const lockTimeout = 5 * time.Minute

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func acquireLock(vaultDir string) (string, bool) {
	return acquireLockWithMode(vaultDir, "daemon")
}

func acquireServerLock(vaultDir string) (string, bool) {
	return acquireLockWithMode(vaultDir, "server")
}

func acquireLockWithMode(vaultDir, mode string) (string, bool) {
	lockPath := filepath.Join(vaultDir, ".data", ".biset.lock")
	os.MkdirAll(filepath.Join(vaultDir, ".data"), 0755) //nolint:errcheck
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		info, statErr := os.Stat(lockPath)
		stale := statErr != nil || time.Since(info.ModTime()) > lockTimeout
		if pid > 0 && isBisetProcess(pid) && !stale {
			return lockPath, false
		}
		os.Remove(lockPath) //nolint:errcheck
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return lockPath, false
	}
	fmt.Fprintf(f, "%d %s", os.Getpid(), mode)
	f.Close()
	return lockPath, true
}

// acquireSyncLock acquires a short-lived lock for a single sync cycle.
// Separate from acquireLock so the daemon's persistent lock is not disturbed.
func acquireSyncLock(vaultDir string) (string, bool) {
	lockPath := filepath.Join(vaultDir, ".data", ".biset-sync.lock")
	os.MkdirAll(filepath.Join(vaultDir, ".data"), 0755) //nolint:errcheck
	if b, err := os.ReadFile(lockPath); err == nil {
		var pid int
		fmt.Sscanf(string(b), "%d", &pid)
		info, statErr := os.Stat(lockPath)
		stale := statErr != nil || time.Since(info.ModTime()) > 30*time.Second
		if pid > 0 && isBisetProcess(pid) && !stale {
			return lockPath, false
		}
		os.Remove(lockPath) //nolint:errcheck
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return lockPath, false
	}
	fmt.Fprintf(f, "%d", os.Getpid())
	f.Close()
	return lockPath, true
}

func newRelayCmd(binPath, dir string) *exec.Cmd {
	cmd := exec.Command(binPath)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devNull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	return cmd
}

func isBisetProcess(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil || proc.Signal(syscall.Signal(0)) != nil {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return filepath.Base(strings.TrimSpace(string(out))) == filepath.Base(exe)
}
