package k8s

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// PodMetadata holds K8s context for enrichment
type PodMetadata struct {
	Name      string
	Namespace string
	NodeName  string
	// can add labels here later if needed
}

// PodCache is a thread-safe bidirectional cache IP <-> Pod
type PodCache struct {
	mu       sync.RWMutex
	ipToMeta map[string]PodMetadata
	uidToIPs map[string][]string // Pod UID -> slice of IPs
}

func NewPodCache() *PodCache {
	return &PodCache{
		ipToMeta: make(map[string]PodMetadata),
		uidToIPs: make(map[string][]string),
	}
}

// Add updates the cache with IP -> Meta and UID -> IPs
func (c *PodCache) Add(pod *corev1.Pod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	uid := string(pod.UID)
	meta := PodMetadata{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		NodeName:  pod.Spec.NodeName,
	}

	var ips []string
	if pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP != "" && podIP.IP != pod.Status.PodIP {
			ips = append(ips, podIP.IP)
		}
	}

	// Clean up old IPs mapped to this UID if they changed
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

// Delete removes a pod entirely using its UID to clean up all associated IPs
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

// GetByIP returns the metadata. If not found (e.g. during the RTM_NEWLINK gap), it returns "unknown".
func (c *PodCache) GetByIP(ip string) PodMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if meta, ok := c.ipToMeta[ip]; ok {
		return meta
	}

	// Graceful fallback for traffic hitting the BPF program before the K8s Informer catches up
	return PodMetadata{
		Name:      "unknown",
		Namespace: "unknown",
		NodeName:  "unknown",
	}
}
