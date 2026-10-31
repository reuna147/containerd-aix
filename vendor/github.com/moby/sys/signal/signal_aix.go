//go:build aix
// +build aix

package signal

import (
	"syscall"
)

// SignalMap is a map of AIX signals.
//
// SIGIOINT is deliberately excluded: on AIX it shares signal number 16 with
// SIGURG, which Go uses as its internal goroutine-preemption signal. Including
// it in the map would cause ctr to forward Go's preemption signal to the task
// whenever SIGURG is delivered to the shim.
var SignalMap = map[string]syscall.Signal{
	"ABRT":     syscall.SIGABRT,
	"AIO":      syscall.Signal(0x17), // SIGAIO / SIGIO / SIGPOLL / SIGPTY
	"ALRM":     syscall.SIGALRM,
	"BUS":      syscall.SIGBUS,
	"CHLD":     syscall.SIGCHLD,
	"CLD":      syscall.SIGCHLD, // alias
	"CONT":     syscall.SIGCONT,
	"DANGER":   syscall.Signal(0x21), // SIGDANGER – low paging space
	"EMT":      syscall.SIGEMT,
	"FPE":      syscall.SIGFPE,
	"HUP":      syscall.SIGHUP,
	"ILL":      syscall.SIGILL,
	"INT":      syscall.SIGINT,
	"IO":       syscall.Signal(0x17), // alias for SIGAIO
	"KILL":     syscall.SIGKILL,
	"MIGRATE":  syscall.Signal(0x23), // SIGMIGRATE
	"MSG":      syscall.Signal(0x1b), // SIGMSG
	"PIPE":     syscall.SIGPIPE,
	"POLL":     syscall.Signal(0x17), // SIGPOLL alias
	"PRE":      syscall.Signal(0x24), // SIGPRE
	"PROF":     syscall.SIGPROF,
	"PWR":      syscall.Signal(0x1d), // SIGPWR
	"QUIT":     syscall.SIGQUIT,
	"RECONFIG": syscall.Signal(0x3a), // SIGRECONFIG
	"SEGV":     syscall.SIGSEGV,
	"STOP":     syscall.SIGSTOP,
	"SYS":      syscall.SIGSYS,
	"TALRM":    syscall.Signal(0x26), // SIGTALRM
	"TERM":     syscall.SIGTERM,
	"TRAP":     syscall.SIGTRAP,
	"TSTP":     syscall.SIGTSTP,
	"TTIN":     syscall.SIGTTIN,
	"TTOU":     syscall.SIGTTOU,
	"URG":      syscall.Signal(0x10), // SIGURG
	"USR1":     syscall.SIGUSR1,
	"USR2":     syscall.SIGUSR2,
	"VIRT":     syscall.Signal(0x25), // SIGVIRT
	"VTALRM":   syscall.SIGVTALRM,
	"WAITING":  syscall.Signal(0x27), // SIGWAITING
	"WINCH":    syscall.Signal(0x1c), // SIGWINCH
	"XCPU":     syscall.SIGXCPU,
	"XFSZ":     syscall.SIGXFSZ,
}
