// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/LiuTangLei/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const kernelBenchMTU = 1280

// kernelBenchTUN belongs to a separate network namespace. Only iperf and its
// kernel TCP/IP stack run there; the engine and outer UDP sockets remain in the
// original host namespace. No production route or firewall rule is changed.
// NativeTun.MTU opens a fresh ioctl socket, so cache the known fixed MTU here.
type kernelBenchTUN struct{ tun.Device }

func (*kernelBenchTUN) MTU() (int, error) { return kernelBenchMTU, nil }

func openKernelBenchTUN(namespace string) (tun.Device, error) {
	if !regexp.MustCompile(`^qbench-[a-z0-9-]{1,40}$`).MatchString(namespace) {
		return nil, fmt.Errorf("kernel benchmark namespace must be an existing qbench-* namespace")
	}
	target, err := os.Open(filepath.Join("/var/run/netns", namespace))
	if err != nil {
		return nil, err
	}
	defer target.Close()
	type result struct {
		tun tun.Device
		err error
	}
	done := make(chan result, 1)
	// Never migrate the Go process. A disposable locked thread changes netns
	// only for TUN creation, restores it before reporting success, and is not
	// returned to the runtime if restoration fails.
	go func() {
		runtime.LockOSThread()
		old, err := os.Open("/proc/self/task/" + fmt.Sprint(unix.Gettid()) + "/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		defer old.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		dev, createErr := tun.CreateTUN("qbench0", kernelBenchMTU)
		if createErr == nil {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err == nil {
				ifr, _ := unix.NewIfreq("qbench0")
				err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr)
				if err == nil {
					ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
					err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
				}
				unix.Close(fd)
			}
			if err != nil {
				dev.Close()
				dev = nil
				createErr = err
			}
		}
		if err := unix.Setns(int(old.Fd()), unix.CLONE_NEWNET); err != nil {
			if dev != nil {
				dev.Close()
			}
			done <- result{err: fmt.Errorf("restore host network namespace: %w", err)}
			return // Go destroys this still-locked OS thread.
		}
		runtime.UnlockOSThread()
		done <- result{tun: dev, err: createErr}
	}()
	r := <-done
	if r.err != nil {
		return nil, r.err
	}
	return &kernelBenchTUN{Device: r.tun}, nil
}
