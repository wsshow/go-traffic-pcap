package storage

import (
	"errors"
	"time"
)

type PacketInfo struct {
	Time         string `json:"time"`
	SrcIP        string `json:"src_ip"`
	SrcPort      string `json:"src_port"`
	SrcMAC       string `json:"src_mac"`
	DstIP        string `json:"dst_ip"`
	DstPort      string `json:"dst_port"`
	DstMAC       string `json:"dst_mac"`
	Protocol     string `json:"protocol"`
	Len          int    `json:"len"`
	Data         []byte `json:"data"`
	EthernetType string `json:"ethernet_type"`
}

type NetworkInterface struct {
	Name      string `json:"name"`
	Desc      string `json:"desc"`
	IP        string `json:"ip"`
	Netmask   string `json:"netmask,omitempty"`
	BroadAddr string `json:"broad_addr,omitempty"`
	P2P       string `json:"p2p,omitempty"`
}

type PcapConfig struct {
	DeviceName  string        `json:"device_name"`
	SnapshotLen int32         `json:"snapshot_len"`
	Timeout     time.Duration `json:"timeout"`
	BPF         string        `json:"bpf"`
	Promiscuous bool          `json:"promiscuous"`
}

func (pc *PcapConfig) Check() error {
	if len(pc.DeviceName) == 0 {
		return errors.New("网卡参数未设置")
	}
	pc.SnapshotLen = 65535
	pc.Timeout = -1
	pc.Promiscuous = true
	return nil
}
