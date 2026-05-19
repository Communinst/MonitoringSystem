package k8s

import (
	"net"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

type PodMetadata struct {
	Name      string
	Namespace string
	NodeName  string
}

type PodCache struct {
	mu       sync.RWMutex
	ipToMeta map[string]PodMetadata
	uidToIPs map[string][]string
}

func NewPodCache() *PodCache {
	return &PodCache{
		ipToMeta: make(map[string]PodMetadata),
		uidToIPs: make(map[string][]string),
	}
}

func (c *PodCache) Add(pod *corev1.Pod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	uid := string(pod.UID)
	meta := PodMetadata{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		NodeName:  pod.Spec.NodeName,
	}

	seen := make(map[string]struct{})
	var ips []string
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP == "" {
			continue
		}
		if _, dup := seen[podIP.IP]; !dup {
			seen[podIP.IP] = struct{}{}
			ips = append(ips, podIP.IP)
		}
	}

	if pod.Status.PodIP != "" {
		if _, dup := seen[pod.Status.PodIP]; !dup {
			ips = append(ips, pod.Status.PodIP)
		}
	}

	if oldIPs, exists := c.uidToIPs[uid]; exists {
		for _, oldIP := range oldIPs {
			delete(c.ipToMeta, oldIP)
		}
	}
	c.uidToIPs[uid] = ips
	for _, ip := range ips {
		c.ipToMeta[ip] = meta
	}
}

func (c *PodCache) Delete(pod *corev1.Pod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	uid := string(pod.UID)
	ips, exists := c.uidToIPs[uid]
	if !exists {
		return
	}

	for _, ip := range ips {
		delete(c.ipToMeta, ip)
	}
	delete(c.uidToIPs, uid)
}

func (c *PodCache) GetByIP(ip string) PodMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if meta, ok := c.ipToMeta[ip]; ok {
		return meta
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil && parsedIP.IsMulticast() {
		return PodMetadata{
			Name:      "mDNS",
			Namespace: "multicast",
			NodeName:  "multicast",
		}
	}
	return PodMetadata{
		Name:      ip,
		Namespace: "external",
		NodeName:  "external",
	}
}
