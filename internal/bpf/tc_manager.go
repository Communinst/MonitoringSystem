package bpf

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TcManager manages dynamic attachment of TC eBPF programs to veth interfaces
type TcManager struct {
	mu    sync.Mutex
	objs  *BpfObjects
	links map[string][]link.Link // map[vethName]links
}

// NewTcManager creates a new manager for TC eBPF programs
func NewTcManager(objs *BpfObjects) *TcManager {
	return &TcManager{
		objs:  objs,
		links: make(map[string][]link.Link),
	}
}

// AttachToVeth attaches TC Ingress and Egress to a specific veth interface
func (m *TcManager) AttachToVeth(vethName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.links[vethName]; exists {
		// Already attached
		return nil
	}

	vethIface, err := net.InterfaceByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to find veth interface %s: %w", vethName, err)
	}

	var attachedLinks []link.Link

	// Ingress (Traffic FROM pod to host)
	tcIn, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objs.TcDnsIngress,
		Attach:    ebpf.AttachTCXIngress,
		Interface: vethIface.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to attach TC Ingress on %s: %w", vethName, err)
	}
	attachedLinks = append(attachedLinks, tcIn)

	// Egress (Traffic FROM host TO pod)
	tcOut, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objs.TcDnsEgress,
		Attach:    ebpf.AttachTCXEgress,
		Interface: vethIface.Index,
	})
	if err != nil {
		tcIn.Close()
		return fmt.Errorf("failed to attach TC Egress on %s: %w", vethName, err)
	}
	attachedLinks = append(attachedLinks, tcOut)

	m.links[vethName] = attachedLinks
	slog.Info("Successfully attached TC to veth", "veth", vethName)

	return nil
}

// DetachFromVeth detaches TC programs from a specific veth interface
func (m *TcManager) DetachFromVeth(vethName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	links, exists := m.links[vethName]
	if !exists {
		return
	}

	for _, l := range links {
		l.Close()
	}
	delete(m.links, vethName)
	slog.Info("Successfully detached TC from veth", "veth", vethName)
}

// DetachAll safely closes all tracked TC links
func (m *TcManager) DetachAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for vethName, links := range m.links {
		for _, l := range links {
			l.Close()
		}
		delete(m.links, vethName)
	}
	slog.Info("Successfully detached TC from all recorded interfaces")
}
