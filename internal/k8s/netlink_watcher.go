package k8s

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NetlinkWatcher struct {
	tcManager *bpf.TcManager
}

func NewNetlinkWatcher(tcManager *bpf.TcManager) *NetlinkWatcher {
	return &NetlinkWatcher{
		tcManager: tcManager,
	}
}

func (w *NetlinkWatcher) Run(ctx context.Context) error {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.LinkSubscribe(ch, done); err != nil {
		return err
	}

	slog.Info("Starting Netlink Watcher for veth interfaces")

	if links, err := netlink.LinkList(); err == nil {
		for _, l := range links {
			w.handleLink(l, unix.RTM_NEWLINK)
		}
	} else {
		slog.Warn("Failed to list existing netlink interfaces", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("Shutting down Netlink Watcher")
			return nil
		case update := <-ch:
			w.handleLink(update.Link, update.Header.Type)
		}
	}
}

func (w *NetlinkWatcher) handleLink(link netlink.Link, eventType uint16) {
	name := link.Attrs().Name
	isVeth := link.Type() == "veth" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "cali") || strings.HasPrefix(name, "eni") || strings.HasPrefix(name, "lxc")

	if !isVeth {
		return
	}

	switch eventType {
	case unix.RTM_NEWLINK:
		if err := w.tcManager.AttachToVeth(name); err != nil {
			slog.Warn("Netlink error attaching TC", "interface", name, "error", err)
		}
	case unix.RTM_DELLINK:
		w.tcManager.DetachFromVeth(name)
	}
}
