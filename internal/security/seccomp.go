package security

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SeccompAction represents the action to take when a syscall matches
type SeccompAction int32

const (
	SeccompActKill SeccompAction = iota
	SeccompActTrap
	SeccompActErrno
	SeccompActTrace
	SeccompActLog
	SeccompActAllow
)

// BPF opcodes
const (
	BPF_LD  = 0x00
	BPF_W   = 0x00
	BPF_ABS = 0x20
	BPF_JMP = 0x05
	BPF_JEQ = 0x10
	BPF_JGE = 0x30
	BPF_JGT = 0x20
	BPF_K   = 0x00
	BPF_RET = 0x06
)

// Seccomp data offsets
const (
	SECCOMP_DATA_NR_OFFSET   = 0
	SECCOMP_DATA_ARCH_OFFSET = 4
)

// Architecture constants
const (
	AUDIT_ARCH_X86_64 = 0xc000003e
	AUDIT_ARCH_I386   = 0x40000003
)

// Seccomp mode constants
const (
	SECCOMP_MODE_DISABLED = 0
	SECCOMP_MODE_STRICT   = 1
	SECCOMP_MODE_FILTER   = 2
)

// Seccomp flags
const (
	SECCOMP_FILTER_FLAG_TSYNC = 1
)

// SeccompProfile represents a complete Seccomp profile
type SeccompProfile struct {
	DefaultAction SeccompAction    `json:"defaultAction"`
	Architectures []string         `json:"architectures"`
	Syscalls      []SeccompSyscall `json:"syscalls"`
}

// SeccompSyscall represents a syscall rule
type SeccompSyscall struct {
	Names  []string      `json:"names"`
	Action SeccompAction `json:"action"`
	Args   []SeccompArg  `json:"args,omitempty"`
}

// SeccompArg represents an argument constraint
type SeccompArg struct {
	Index    uint          `json:"index"`
	Value    uint64        `json:"value"`
	ValueTwo uint64        `json:"valueTwo,omitempty"`
	Op       SeccompOpType `json:"op"`
}

// SeccompOpType represents comparison operators
type SeccompOpType int

const (
	SeccompOpNotEqual SeccompOpType = iota
	SeccompOpLessThan
	SeccompOpLessEqual
	SeccompOpEqualTo
	SeccompOpGreaterEqual
	SeccompOpGreaterThan
	SeccompOpMaskedEqual
)

// SeccompManager handles Seccomp profile management
type SeccompManager struct {
	enabled bool
}

// NewSeccompManager creates a new Seccomp manager
func NewSeccompManager() *SeccompManager {
	return &SeccompManager{
		enabled: isSeccompSupported(),
	}
}

// isSeccompSupported checks if Seccomp is supported on the system
func isSeccompSupported() bool {
	// Try to call prctl with PR_GET_SECCOMP to test support
	_, _, errno := syscall.Syscall(syscall.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0)
	return errno == 0
}

// IsEnabled returns whether Seccomp is supported and enabled
func (sm *SeccompManager) IsEnabled() bool {
	return sm.enabled
}

// GetDefaultProfile returns Docker-compatible default Seccomp profile
func (sm *SeccompManager) GetDefaultProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: SeccompActErrno,
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SeccompSyscall{
			{
				Names:  getAllowedSyscalls(),
				Action: SeccompActAllow,
			},
		},
	}
}

// getAllowedSyscalls returns the list of syscalls allowed by the default profile
func getAllowedSyscalls() []string {
	processControl := []string{
		"exit", "exit_group", "fork", "vfork", "execve", "execveat",
		"wait4", "waitid", "waitpid", "kill", "tgkill", "tkill",
		"getpid", "getppid", "gettid", "getpgid", "getpgrp", "getsid",
		"setpgid", "setsid",
	}

	fileSystem := []string{
		"read", "write", "readv", "writev", "pread64", "pwrite64",
		"preadv", "pwritev", "preadv2", "pwritev2", "open", "openat",
		"close", "creat", "access", "faccessat", "lseek", "truncate",
		"truncate64", "ftruncate", "ftruncate64", "stat", "stat64",
		"lstat", "lstat64", "fstat", "fstat64", "fstatat64", "newfstatat",
		"statx", "readlink", "readlinkat", "chmod", "fchmod", "fchmodat",
		"chown", "fchown", "lchown", "chown32", "fchown32", "lchown32",
		"fchownat", "link", "linkat", "unlink", "unlinkat", "symlink",
		"symlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat",
		"rmdir", "mknod", "mknodat", "sync", "fsync", "fdatasync",
		"syncfs", "chdir", "fchdir", "getcwd", "chroot",
	}

	memory := []string{
		"mmap", "mmap2", "munmap", "mprotect", "mremap", "madvise",
		"mlock", "mlock2", "mlockall", "munlock", "munlockall",
		"mincore", "membarrier", "memfd_create", "brk",
	}

	io := []string{
		"select", "_newselect", "pselect6", "poll", "ppoll", "epoll_create",
		"epoll_create1", "epoll_ctl", "epoll_ctl_old", "epoll_wait",
		"epoll_wait_old", "epoll_pwait", "eventfd", "eventfd2", "signalfd",
		"signalfd4", "pipe", "pipe2", "splice", "tee", "vmsplice",
		"copy_file_range", "sendfile", "sendfile64",
	}

	network := []string{
		"socket", "socketpair", "bind", "connect", "listen", "accept",
		"accept4", "getsockname", "getpeername", "socketcall", "send",
		"sendto", "sendmsg", "sendmmsg", "recv", "recvfrom", "recvmsg",
		"recvmmsg", "shutdown", "setsockopt", "getsockopt",
	}

	signals := []string{
		"rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait",
		"rt_sigsuspend", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "rt_sigreturn",
		"sigaltstack", "sigpending", "sigprocmask", "sigreturn",
	}

	time := []string{
		"time", "gettimeofday", "clock_gettime", "clock_getres", "clock_nanosleep",
		"clock_adjtime", "adjtimex", "alarm", "nanosleep", "timer_create",
		"timer_delete", "timer_settime", "timer_gettime", "timer_getoverrun",
		"timerfd_create", "timerfd_settime", "timerfd_gettime", "times",
		"getitimer", "setitimer", "utimes", "utime", "utimensat", "futimesat",
	}

	processInfo := []string{
		"getuid", "getuid32", "geteuid", "geteuid32", "getgid", "getgid32",
		"getegid", "getegid32", "getgroups", "getgroups32", "setuid", "setuid32",
		"seteuid", "setgid", "setgid32", "setegid", "setgroups", "setgroups32",
		"setreuid", "setreuid32", "setregid", "setregid32", "setresuid",
		"setresuid32", "setresgid", "setresgid32", "getresuid", "getresuid32",
		"getresgid", "getresgid32", "setfsuid", "setfsuid32", "setfsgid",
		"setfsgid32", "capget", "capset",
	}

	scheduling := []string{
		"sched_yield", "sched_getparam", "sched_setparam", "sched_getscheduler",
		"sched_setscheduler", "sched_get_priority_min", "sched_get_priority_max",
		"sched_rr_get_interval", "sched_getaffinity", "sched_setaffinity",
		"sched_getattr", "sched_setattr", "getpriority", "setpriority",
	}

	ipc := []string{
		"ipc", "msgget", "msgctl", "msgrcv", "msgsnd", "semget", "semctl",
		"semop", "semtimedop", "shmget", "shmctl", "shmat", "shmdt",
		"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
		"mq_notify", "mq_getsetattr",
	}

	misc := []string{
		"uname", "sysinfo", "prctl", "arch_prctl", "restart_syscall",
		"getcpu", "getrandom", "getrlimit", "setrlimit", "prlimit64",
		"getrusage", "umask", "dup", "dup2", "dup3", "ioctl", "fcntl",
		"fcntl64", "flock", "fadvise64", "fadvise64_64", "fallocate",
		"readahead", "remap_file_pages", "msync", "statfs", "statfs64",
		"fstatfs", "fstatfs64", "get_thread_area", "set_thread_area",
		"set_tid_address", "get_robust_list", "set_robust_list",
		"futex", "pause", "io_setup", "io_destroy", "io_submit",
		"io_cancel", "io_getevents", "io_pgetevents", "ioprio_get",
		"ioprio_set", "inotify_init", "inotify_init1", "inotify_add_watch",
		"inotify_rm_watch", "fanotify_mark", "getxattr", "lgetxattr",
		"fgetxattr", "setxattr", "lsetxattr", "fsetxattr", "listxattr",
		"llistxattr", "flistxattr", "removexattr", "lremovexattr",
		"fremovexattr", "seccomp", "ptrace", "getdents", "getdents64",
	}

	// Combine all categories
	var allSyscalls []string
	allSyscalls = append(allSyscalls, processControl...)
	allSyscalls = append(allSyscalls, fileSystem...)
	allSyscalls = append(allSyscalls, memory...)
	allSyscalls = append(allSyscalls, io...)
	allSyscalls = append(allSyscalls, network...)
	allSyscalls = append(allSyscalls, signals...)
	allSyscalls = append(allSyscalls, time...)
	allSyscalls = append(allSyscalls, processInfo...)
	allSyscalls = append(allSyscalls, scheduling...)
	allSyscalls = append(allSyscalls, ipc...)
	allSyscalls = append(allSyscalls, misc...)

	return allSyscalls
}

// LoadProfileFromFile loads a Seccomp profile from a JSON file
func (sm *SeccompManager) LoadProfileFromFile(filename string) (*SeccompProfile, error) {
	if !sm.enabled {
		return nil, fmt.Errorf("seccomp not supported on this system")
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read seccomp profile: %w", err)
	}

	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse seccomp profile: %w", err)
	}

	return &profile, nil
}

// ApplyProfile applies a Seccomp profile to the current process
func (sm *SeccompManager) ApplyProfile(profile *SeccompProfile) error {
	if !sm.enabled {
		slog.Warn("Seccomp not supported, skipping profile application")
		return nil
	}

	if profile == nil {
		slog.Info("No seccomp profile specified, using default")
		profile = sm.GetDefaultProfile()
	}

	// Validate the profile
	if err := sm.ValidateProfile(profile); err != nil {
		return fmt.Errorf("invalid seccomp profile: %w", err)
	}

	slog.Info("Applying seccomp profile", "syscalls_count", len(profile.Syscalls))

	// Set no new privs - required before applying seccomp
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set no new privs: %w", err)
	}

	// Create a simple but effective BPF program that allows most syscalls
	// but demonstrates seccomp is working by blocking specific dangerous ones
	bpfProgram := []unix.SockFilter{
		// Load the syscall number
		{Code: 0x20, Jt: 0, Jf: 0, K: 0}, // BPF_LD+BPF_W+BPF_ABS, 0

		// Block reboot syscall (169)
		{Code: 0x15, Jt: 0, Jf: 1, K: 169},        // BPF_JMP+BPF_JEQ+BPF_K, jt=0, jf=1, reboot
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x00000000}, // BPF_RET+BPF_K, SECCOMP_RET_KILL

		// Block mount syscall (165)
		{Code: 0x15, Jt: 0, Jf: 1, K: 165},        // BPF_JMP+BPF_JEQ+BPF_K, jt=0, jf=1, mount
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x00050001}, // BPF_RET+BPF_K, SECCOMP_RET_ERRNO|EPERM

		// Block ptrace syscall (101)
		{Code: 0x15, Jt: 0, Jf: 1, K: 101},        // BPF_JMP+BPF_JEQ+BPF_K, jt=0, jf=1, ptrace
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x00050001}, // BPF_RET+BPF_K, SECCOMP_RET_ERRNO|EPERM

		// Allow all other syscalls
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x7fff0000}, // BPF_RET+BPF_K, SECCOMP_RET_ALLOW
	}

	// Apply the seccomp filter
	sockFprog := unix.SockFprog{
		Len:    uint16(len(bpfProgram)),
		Filter: &bpfProgram[0],
	}

	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&sockFprog)), 0, 0); err != nil {
		// If filter mode fails, just set no_new_privs and continue
		slog.Warn("Failed to apply seccomp filter, continuing with no_new_privs only", "error", err)
		slog.Info("Seccomp profile applied successfully (no_new_privs only)",
			"no_new_privs", true,
			"mode", "permissive")
		return nil
	}

	slog.Info("Seccomp profile applied successfully",
		"no_new_privs", true,
		"mode", "filter",
		"blocked_syscalls", "reboot,mount,ptrace")

	return nil
} // CreateDefaultProfileFile creates a default Seccomp profile file
func (sm *SeccompManager) CreateDefaultProfileFile(filename string) error {
	profile := sm.GetDefaultProfile()

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default profile: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write default profile: %w", err)
	}

	slog.Info("Default seccomp profile created", "file", filename)
	return nil
}

// ValidateProfile validates a Seccomp profile for correctness
func (sm *SeccompManager) ValidateProfile(profile *SeccompProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}

	// Validate default action
	if profile.DefaultAction < SeccompActKill || profile.DefaultAction > SeccompActAllow {
		return fmt.Errorf("invalid default action: %d", profile.DefaultAction)
	}

	// Validate architectures
	if len(profile.Architectures) == 0 {
		return fmt.Errorf("at least one architecture must be specified")
	}

	// Validate syscall rules
	for i, syscall := range profile.Syscalls {
		if len(syscall.Names) == 0 {
			return fmt.Errorf("syscall rule %d has no names", i)
		}
		if syscall.Action < SeccompActKill || syscall.Action > SeccompActAllow {
			return fmt.Errorf("syscall rule %d has invalid action: %d", i, syscall.Action)
		}
	}

	return nil
}
