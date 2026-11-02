package helper

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Every system command the API runs (nft, wg, ip, iptables, ss, nsenter…) goes through Command, so
// none can hang the API forever: a stuck one (a wedged netlink call, a held xtables lock, a blocked
// host namespace) is killed after ExecTimeout and returns an error instead. Many run under a lock —
// the firewall apply among them — where one hang would silently stall every later change.
// TestNoUntimedCommands keeps plain exec.Command out of the code.

// Cmd is an exec.Cmd bounded by a time limit. Run, Output, CombinedOutput and Wait release the
// limit's timer when the command ends.
type Cmd struct {
	*exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
	limit  time.Duration
}

// Command is exec.Command with ExecTimeout.
func Command(name string, args ...string) *Cmd { return commandWithin(ExecTimeout, name, args...) }

func commandWithin(limit time.Duration, name string, args ...string) *Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	c := exec.CommandContext(ctx, name, args...)
	c.WaitDelay = ExecWaitDelay
	return &Cmd{Cmd: c, ctx: ctx, cancel: cancel, limit: limit}
}

// done releases the timer and names a timeout in the error.
func (c *Cmd) done(err error) error {
	timedOut := c.ctx.Err() == context.DeadlineExceeded
	c.cancel()
	if err != nil && timedOut {
		return fmt.Errorf("%s: no answer within %v, stopped: %w", c.Path, c.limit, err)
	}
	return err
}

func (c *Cmd) Run() error  { return c.done(c.Cmd.Run()) }
func (c *Cmd) Wait() error { return c.done(c.Cmd.Wait()) }

func (c *Cmd) Output() ([]byte, error) {
	out, err := c.Cmd.Output()
	return out, c.done(err)
}

func (c *Cmd) CombinedOutput() ([]byte, error) {
	out, err := c.Cmd.CombinedOutput()
	return out, c.done(err)
}
