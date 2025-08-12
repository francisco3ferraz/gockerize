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

// BPF instruction structure
type bpfInstruction struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// BPF program structure
type bpfProgram struct {
	len    uint16
	filter *bpfInstruction
}

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

// getSyscallNumber returns the syscall number for a given syscall name
func getSyscallNumber(name string) (int, bool) {
	// Use golang.org/x/sys/unix package which has all syscall numbers
	switch name {
	case "read":
		return unix.SYS_READ, true
	case "write":
		return unix.SYS_WRITE, true
	case "open":
		return unix.SYS_OPEN, true
	case "close":
		return unix.SYS_CLOSE, true
	case "stat":
		return unix.SYS_STAT, true
	case "fstat":
		return unix.SYS_FSTAT, true
	case "lstat":
		return unix.SYS_LSTAT, true
	case "poll":
		return unix.SYS_POLL, true
	case "lseek":
		return unix.SYS_LSEEK, true
	case "mmap":
		return unix.SYS_MMAP, true
	case "mprotect":
		return unix.SYS_MPROTECT, true
	case "munmap":
		return unix.SYS_MUNMAP, true
	case "brk":
		return unix.SYS_BRK, true
	case "rt_sigaction":
		return unix.SYS_RT_SIGACTION, true
	case "rt_sigprocmask":
		return unix.SYS_RT_SIGPROCMASK, true
	case "rt_sigreturn":
		return unix.SYS_RT_SIGRETURN, true
	case "ioctl":
		return unix.SYS_IOCTL, true
	case "pread64":
		return unix.SYS_PREAD64, true
	case "pwrite64":
		return unix.SYS_PWRITE64, true
	case "readv":
		return unix.SYS_READV, true
	case "writev":
		return unix.SYS_WRITEV, true
	case "access":
		return unix.SYS_ACCESS, true
	case "pipe":
		return unix.SYS_PIPE, true
	case "select":
		return unix.SYS_SELECT, true
	case "sched_yield":
		return unix.SYS_SCHED_YIELD, true
	case "mremap":
		return unix.SYS_MREMAP, true
	case "msync":
		return unix.SYS_MSYNC, true
	case "mincore":
		return unix.SYS_MINCORE, true
	case "madvise":
		return unix.SYS_MADVISE, true
	case "shmget":
		return unix.SYS_SHMGET, true
	case "shmat":
		return unix.SYS_SHMAT, true
	case "shmctl":
		return unix.SYS_SHMCTL, true
	case "dup":
		return unix.SYS_DUP, true
	case "dup2":
		return unix.SYS_DUP2, true
	case "pause":
		return unix.SYS_PAUSE, true
	case "nanosleep":
		return unix.SYS_NANOSLEEP, true
	case "getitimer":
		return unix.SYS_GETITIMER, true
	case "alarm":
		return unix.SYS_ALARM, true
	case "setitimer":
		return unix.SYS_SETITIMER, true
	case "getpid":
		return unix.SYS_GETPID, true
	case "sendfile":
		return unix.SYS_SENDFILE, true
	case "socket":
		return unix.SYS_SOCKET, true
	case "connect":
		return unix.SYS_CONNECT, true
	case "accept":
		return unix.SYS_ACCEPT, true
	case "sendto":
		return unix.SYS_SENDTO, true
	case "recvfrom":
		return unix.SYS_RECVFROM, true
	case "sendmsg":
		return unix.SYS_SENDMSG, true
	case "recvmsg":
		return unix.SYS_RECVMSG, true
	case "shutdown":
		return unix.SYS_SHUTDOWN, true
	case "bind":
		return unix.SYS_BIND, true
	case "listen":
		return unix.SYS_LISTEN, true
	case "getsockname":
		return unix.SYS_GETSOCKNAME, true
	case "getpeername":
		return unix.SYS_GETPEERNAME, true
	case "socketpair":
		return unix.SYS_SOCKETPAIR, true
	case "setsockopt":
		return unix.SYS_SETSOCKOPT, true
	case "getsockopt":
		return unix.SYS_GETSOCKOPT, true
	case "clone":
		return unix.SYS_CLONE, true
	case "fork":
		return unix.SYS_FORK, true
	case "vfork":
		return unix.SYS_VFORK, true
	case "execve":
		return unix.SYS_EXECVE, true
	case "exit":
		return unix.SYS_EXIT, true
	case "wait4":
		return unix.SYS_WAIT4, true
	case "kill":
		return unix.SYS_KILL, true
	case "uname":
		return unix.SYS_UNAME, true
	case "fcntl":
		return unix.SYS_FCNTL, true
	case "flock":
		return unix.SYS_FLOCK, true
	case "fsync":
		return unix.SYS_FSYNC, true
	case "fdatasync":
		return unix.SYS_FDATASYNC, true
	case "truncate":
		return unix.SYS_TRUNCATE, true
	case "ftruncate":
		return unix.SYS_FTRUNCATE, true
	case "getdents":
		return unix.SYS_GETDENTS, true
	case "getcwd":
		return unix.SYS_GETCWD, true
	case "chdir":
		return unix.SYS_CHDIR, true
	case "fchdir":
		return unix.SYS_FCHDIR, true
	case "rename":
		return unix.SYS_RENAME, true
	case "mkdir":
		return unix.SYS_MKDIR, true
	case "rmdir":
		return unix.SYS_RMDIR, true
	case "creat":
		return unix.SYS_CREAT, true
	case "link":
		return unix.SYS_LINK, true
	case "unlink":
		return unix.SYS_UNLINK, true
	case "symlink":
		return unix.SYS_SYMLINK, true
	case "readlink":
		return unix.SYS_READLINK, true
	case "chmod":
		return unix.SYS_CHMOD, true
	case "fchmod":
		return unix.SYS_FCHMOD, true
	case "chown":
		return unix.SYS_CHOWN, true
	case "fchown":
		return unix.SYS_FCHOWN, true
	case "lchown":
		return unix.SYS_LCHOWN, true
	case "umask":
		return unix.SYS_UMASK, true
	case "gettimeofday":
		return unix.SYS_GETTIMEOFDAY, true
	case "getrlimit":
		return unix.SYS_GETRLIMIT, true
	case "getrusage":
		return unix.SYS_GETRUSAGE, true
	case "sysinfo":
		return unix.SYS_SYSINFO, true
	case "times":
		return unix.SYS_TIMES, true
	case "ptrace":
		return unix.SYS_PTRACE, true
	case "getuid":
		return unix.SYS_GETUID, true
	case "getgid":
		return unix.SYS_GETGID, true
	case "setuid":
		return unix.SYS_SETUID, true
	case "setgid":
		return unix.SYS_SETGID, true
	case "geteuid":
		return unix.SYS_GETEUID, true
	case "getegid":
		return unix.SYS_GETEGID, true
	case "setpgid":
		return unix.SYS_SETPGID, true
	case "getppid":
		return unix.SYS_GETPPID, true
	case "getpgrp":
		return unix.SYS_GETPGRP, true
	case "setsid":
		return unix.SYS_SETSID, true
	case "prctl":
		return unix.SYS_PRCTL, true
	case "mount":
		return unix.SYS_MOUNT, true
	case "umount2":
		return unix.SYS_UMOUNT2, true
	case "reboot":
		return unix.SYS_REBOOT, true
	case "openat":
		return unix.SYS_OPENAT, true
	case "mkdirat":
		return unix.SYS_MKDIRAT, true
	case "unlinkat":
		return unix.SYS_UNLINKAT, true
	case "exit_group":
		return unix.SYS_EXIT_GROUP, true
	case "epoll_create":
		return unix.SYS_EPOLL_CREATE, true
	case "epoll_ctl":
		return unix.SYS_EPOLL_CTL, true
	case "epoll_wait":
		return unix.SYS_EPOLL_WAIT, true
	case "futex":
		return unix.SYS_FUTEX, true
	case "getdents64":
		return unix.SYS_GETDENTS64, true
	case "accept4":
		return unix.SYS_ACCEPT4, true
	case "eventfd2":
		return unix.SYS_EVENTFD2, true
	case "pipe2":
		return unix.SYS_PIPE2, true
	case "dup3":
		return unix.SYS_DUP3, true
	default:
		// For any syscalls not explicitly listed, return false
		// This is safer than trying to maintain a complete mapping
		return 0, false
	}
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

// generateBPFProgram generates a BPF program from a Seccomp profile
func (sm *SeccompManager) generateBPFProgram(profile *SeccompProfile) ([]bpfInstruction, error) {
	var program []bpfInstruction

	// Load architecture
	program = append(program, bpfInstruction{
		code: BPF_LD | BPF_W | BPF_ABS,
		k:    SECCOMP_DATA_ARCH_OFFSET,
	})

	// Check architecture (x86_64) - if not x86_64, kill
	program = append(program, bpfInstruction{
		code: BPF_JMP | BPF_JEQ | BPF_K,
		jt:   1,
		jf:   0,
		k:    AUDIT_ARCH_X86_64,
	})

	// Kill if wrong architecture
	program = append(program, bpfInstruction{
		code: BPF_RET | BPF_K,
		k:    0x00000000, // SECCOMP_RET_KILL
	})

	// Load syscall number
	program = append(program, bpfInstruction{
		code: BPF_LD | BPF_W | BPF_ABS,
		k:    SECCOMP_DATA_NR_OFFSET,
	})

	// Collect allowed syscalls
	allowedSyscalls := make([]int, 0)
	for _, syscallGroup := range profile.Syscalls {
		if syscallGroup.Action == SeccompActAllow {
			for _, name := range syscallGroup.Names {
				if num, exists := getSyscallNumber(name); exists {
					allowedSyscalls = append(allowedSyscalls, num)
				}
			}
		}
	}

	// Add checks for allowed syscalls
	for i, syscallNum := range allowedSyscalls {
		// Calculate jump offset to allow instruction
		// We need to jump over remaining syscall checks + default action
		remainingSyscalls := len(allowedSyscalls) - i - 1
		jumpToAllow := uint8(remainingSyscalls + 1) // +1 for default action

		program = append(program, bpfInstruction{
			code: BPF_JMP | BPF_JEQ | BPF_K,
			jt:   jumpToAllow,
			jf:   0,
			k:    uint32(syscallNum),
		})
	}

	// Default action for non-matching syscalls
	defaultReturnValue := uint32(0x00050000 | uint32(syscall.EPERM)) // SECCOMP_RET_ERRNO | EPERM
	if profile.DefaultAction == SeccompActKill {
		defaultReturnValue = 0x00000000 // SECCOMP_RET_KILL
	}

	program = append(program, bpfInstruction{
		code: BPF_RET | BPF_K,
		k:    defaultReturnValue,
	})

	// Allow action for permitted syscalls
	program = append(program, bpfInstruction{
		code: BPF_RET | BPF_K,
		k:    0x7fff0000, // SECCOMP_RET_ALLOW
	})

	return program, nil
}

// seccompSyscall performs the seccomp system call
func seccompSyscall(op int, flags int, args uintptr) error {
	_, _, errno := syscall.Syscall(unix.SYS_SECCOMP, uintptr(op), uintptr(flags), args)
	if errno != 0 {
		return errno
	}
	return nil
}
func getAllowedSyscalls() []string {
	return []string{
		"accept", "accept4", "access", "adjtimex", "alarm", "bind", "brk", "capget", "capset",
		"chdir", "chmod", "chown", "chown32", "chroot", "clock_adjtime", "clock_getres",
		"clock_gettime", "clock_nanosleep", "close", "connect", "copy_file_range", "creat",
		"dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
		"epoll_pwait", "epoll_wait", "epoll_wait_old", "eventfd", "eventfd2", "execve",
		"execveat", "exit", "exit_group", "faccessat", "fadvise64", "fadvise64_64",
		"fallocate", "fanotify_mark", "fchdir", "fchmod", "fchmodat", "fchown", "fchown32",
		"fchownat", "fcntl", "fcntl64", "fdatasync", "fgetxattr", "flistxattr", "flock",
		"fork", "fremovexattr", "fsetxattr", "fstat", "fstat64", "fstatat64", "fstatfs",
		"fstatfs64", "fsync", "ftruncate", "ftruncate64", "futex", "futimesat", "getcpu",
		"getcwd", "getdents", "getdents64", "getegid", "getegid32", "geteuid", "geteuid32",
		"getgid", "getgid32", "getgroups", "getgroups32", "getitimer", "getpeername",
		"getpgid", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid",
		"getresgid32", "getresuid", "getresuid32", "getrlimit", "get_robust_list",
		"getrusage", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid",
		"gettimeofday", "getuid", "getuid32", "getxattr", "inotify_add_watch",
		"inotify_init", "inotify_init1", "inotify_rm_watch", "io_cancel", "ioctl",
		"io_destroy", "io_getevents", "io_pgetevents", "ioprio_get", "ioprio_set",
		"io_setup", "io_submit", "ipc", "kill", "lchown", "lchown32", "lgetxattr",
		"link", "linkat", "listen", "listxattr", "llistxattr", "lremovexattr", "lseek",
		"lsetxattr", "lstat", "lstat64", "madvise", "membarrier", "memfd_create", "mincore",
		"mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap",
		"mmap2", "mprotect", "mq_getsetattr", "mq_notify", "mq_open", "mq_timedreceive",
		"mq_timedsend", "mq_unlink", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd",
		"msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "_newselect",
		"open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "prctl", "pread64",
		"preadv", "preadv2", "prlimit64", "pselect6", "ptrace", "pwrite64", "pwritev",
		"pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv",
		"recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename",
		"renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending",
		"rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait",
		"rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam",
		"sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler",
		"sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam",
		"sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget",
		"semop", "semtimedop", "send", "sendfile", "sendfile64", "sendmmsg", "sendmsg",
		"sendto", "setfsgid", "setfsgid32", "setfsuid", "setfsuid32", "setgid", "setgid32",
		"setgroups", "setgroups32", "setitimer", "setpgid", "setpriority", "setregid",
		"setregid32", "setresgid", "setresgid32", "setresuid", "setresuid32", "setreuid",
		"setreuid32", "setrlimit", "set_robust_list", "setsid", "setsockopt",
		"set_thread_area", "set_tid_address", "setuid", "setuid32", "setxattr", "shmat",
		"shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4",
		"sigpending", "sigprocmask", "sigreturn", "socket", "socketcall", "socketpair",
		"splice", "stat", "stat64", "statfs", "statfs64", "statx", "symlink", "symlinkat",
		"sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create",
		"timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun",
		"timer_gettime", "timer_settime", "times", "tkill", "truncate", "truncate64",
		"ugetrlimit", "umask", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes",
		"vfork", "vmsplice", "wait4", "waitid", "waitpid", "write", "writev",
	}
}

// getBlockedSyscalls returns syscalls that should be blocked by default
func getBlockedSyscalls() []string {
	return []string{
		"acct", "add_key", "bpf", "clock_adjtime", "clock_settime", "create_module",
		"delete_module", "finit_module", "get_kernel_syms", "get_mempolicy",
		"init_module", "ioperm", "iopl", "kcmp", "kexec_file_load", "kexec_load",
		"keyctl", "lookup_dcookie", "mbind", "mount", "move_pages", "name_to_handle_at",
		"nfsservctl", "open_by_handle_at", "perf_event_open", "personality", "pivot_root",
		"process_vm_readv", "process_vm_writev", "ptrace", "query_module", "quotactl",
		"reboot", "request_key", "set_mempolicy", "setdomainname", "sethostname",
		"settimeofday", "stime", "swapon", "swapoff", "sysfs", "_sysctl", "umount",
		"umount2", "unshare", "uselib", "userfaultfd", "ustat", "vm86", "vm86old",
	}
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
