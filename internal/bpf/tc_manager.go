package bpf

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)


type TcManager struct {
	mu    sync.Mutex
	objs  *BpfObjects
	links map[string][]link.Link // map[vethName]links
}


func NewTcManager(objs *BpfObjects) *TcManager {
	return &TcManager{
		objs:  objs,
		links: make(map[string][]link.Link),
	}
}


func (m *TcManager) AttachToVeth(vethName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.links[vethName]; exists {
		return nil
	}

	vethIface, err := net.InterfaceByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to find veth interface %s: %w", vethName, err)
	}

	var attachedLinks []link.Link


	tcIn, err := link.AttachTCX(link.TCXOptions{
		Program:   m.objs.TcDnsIngress,
		Attach:    ebpf.AttachTCXIngress,
		Interface: vethIface.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to attach TC Ingress on %s: %w", vethName, err)
	}
	attachedLinks = append(attachedLinks, tcIn)


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
