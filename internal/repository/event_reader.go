package repository

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/Communinst/MonitoringSystem/internal/k8s"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type DnsEventLog struct {
	TimestampNs uint64          `json:"timestamp_ns"`
	LatencyNs   uint64          `json:"latency_ns,omitempty"`
	SrcIP       string          `json:"src_ip"`
	DstIP       string          `json:"dst_ip"`
	SrcPod      k8s.PodMetadata `json:"src_pod"`
	DstPod      k8s.PodMetadata `json:"dst_pod"`
	QType       uint32          `json:"qtype"`
	QName       string          `json:"qname"`
	Status      string          `json:"status"`
}

type EventReader struct {
	ringBuf    *ringbuf.Reader
	resolver   IPResolver
	pusher     *LokiPusher
	bootTimeNs uint64
}

func NewEventReader(bpfMaps *bpf.BpfMaps, resolver IPResolver, pusher *LokiPusher) (*EventReader, error) {
	rb, err := ringbuf.NewReader(bpfMaps.DnsEventRingbuf)
	if err != nil {
		return nil, err
	}

	return &EventReader{
		ringBuf:    rb,
		resolver:   resolver,
		pusher:     pusher,
		bootTimeNs: getBootTimeNs(),
	}, nil
}

func (er *EventReader) Run(ctx context.Context) {
	defer er.ringBuf.Close()

	slog.Info("Started DNS event ringbuffer reader")

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping DNS event ringbuffer reader")
			return
		default:
			record, err := er.ringBuf.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					slog.Info("Ringbuffer closed")
					return
				}
				slog.Error("Error reading from ringbuf", "error", err)
				continue
			}

			var event bpf.BpfDnsEventFull
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				slog.Error("Failed to decode ringbuf event", "error", err)
				continue
			}

			srcIP := parseBpfIp(event.SrcIp.IpV, event.SrcIp.Ip.Ipv4)
			dstIP := parseBpfIp(event.DstIp.IpV, event.DstIp.Ip.Ipv4)

			qnameLen := event.Event.QnameLen
			if qnameLen > 0 && event.Event.Qname[qnameLen-1] == 0 {
				qnameLen--
			}

			// Cut off the first byte from qname
			qname := ""
			if qnameLen > 1 {
				qname = string(event.Event.Qname[1:qnameLen])
			}

			srcMeta := er.resolver.GetByIP(srcIP)
			dstMeta := er.resolver.GetByIP(dstIP)

			logEntry := DnsEventLog{
				TimestampNs: event.TimestampNs,
				LatencyNs:   event.LatencyNs,
				SrcIP:       srcIP,
				DstIP:       dstIP,
				SrcPod:      srcMeta,
				DstPod:      dstMeta,
				QType:       event.Qtype,
				QName:       qname,
				Status:      parseStatus(event.Status),
			}

			jsonBytes, _ := json.Marshal(logEntry)

			if er.pusher != nil && er.pusher.lokiURL != "" {
				unixNs := er.bootTimeNs + event.TimestampNs
				er.pusher.Add(unixNs, string(jsonBytes))
			} else {
				os.Stdout.Write(append(jsonBytes, '\n'))
			}
		}
	}
}

func parseBpfIp(ipV uint32, ipv4 uint32) string {
	if ipV == 4 {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, ipv4)
		return net.IP(ipBytes).String()
	}
	return "unknown"
}

func getBootTimeNs() uint64 {
	var realtime unix.Timespec
	var monotonic unix.Timespec
	unix.ClockGettime(unix.CLOCK_REALTIME, &realtime)
	unix.ClockGettime(unix.CLOCK_BOOTTIME, &monotonic)

	realtimeNs := uint64(realtime.Sec)*1e9 + uint64(realtime.Nsec)
	monotonicNs := uint64(monotonic.Sec)*1e9 + uint64(monotonic.Nsec)
	return realtimeNs - monotonicNs
}

func parseStatus(status uint16) string {
	switch status {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "RESPONSE_OTHER"
	case 7:
		return "QUERY"
	default:
		return "UNKNOWN"
	}
}
