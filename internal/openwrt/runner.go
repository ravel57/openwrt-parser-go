package openwrt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Runner interface {
	Run(ctx context.Context, script string) (string, error)
	Close() error
}

type LocalRunner struct{}

func (LocalRunner) Run(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("local command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
func (LocalRunner) Close() error { return nil }

type SSHRunner struct {
	addr            string
	user            string
	pass            string
	keyFile         string
	insecureHostKey bool
	timeout         time.Duration
}

func NewSSHRunner(addr, user, pass, keyFile string, insecureHostKey bool, timeout time.Duration) *SSHRunner {
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	return &SSHRunner{addr: addr, user: user, pass: pass, keyFile: keyFile, insecureHostKey: insecureHostKey, timeout: timeout}
}

func (r *SSHRunner) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if r.keyFile != "" {
		b, err := os.ReadFile(r.keyFile)
		if err != nil {
			return nil, fmt.Errorf("read SSH key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if r.pass != "" {
		methods = append(methods, ssh.Password(r.pass))
	}
	if len(methods) == 0 {
		return nil, errors.New("no OpenWrt SSH authentication configured")
	}
	return methods, nil
}

func (r *SSHRunner) Run(ctx context.Context, script string) (string, error) {
	auth, err := r.authMethods()
	if err != nil {
		return "", err
	}
	hostKey := ssh.InsecureIgnoreHostKey()
	if !r.insecureHostKey {
		return "", errors.New("strict SSH host key verification is not configured; set APP_OPENWRT_INSECURE_HOST_KEY=true or use local mode")
	}
	cfg := &ssh.ClientConfig{User: r.user, Auth: auth, HostKeyCallback: hostKey, Timeout: r.timeout}

	d := net.Dialer{Timeout: r.timeout}
	raw, err := d.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return "", fmt.Errorf("dial OpenWrt SSH: %w", err)
	}
	defer raw.Close()

	conn, chans, reqs, err := ssh.NewClientConn(raw, r.addr, cfg)
	if err != nil {
		return "", fmt.Errorf("OpenWrt SSH handshake: %w", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("OpenWrt SSH session: %w", err)
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() { b, e := sess.CombinedOutput(script); ch <- result{b, e} }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return string(res.out), fmt.Errorf("remote command failed: %w: %s", res.err, strings.TrimSpace(string(res.out)))
		}
		return string(res.out), nil
	}
}
func (r *SSHRunner) Close() error { return nil }
