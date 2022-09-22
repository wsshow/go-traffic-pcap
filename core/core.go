package core

import (
	"fmt"
	"go-traffic-pcap/global"
	"go-traffic-pcap/storage"
	"go-traffic-pcap/utils"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type LPCap struct {
	bPCapRunning bool
	outDir       string
	handle       *pcap.Handle
	dumpFile     *os.File
	packetWriter *pcapgo.Writer
	ch           chan gopacket.Packet
	curPcapPath  string
}

var (
	err   error
	lpcap *LPCap
	once  sync.Once
)

func Get() *LPCap {
	once.Do(func() {
		lpcap = &LPCap{
			handle:       nil,
			dumpFile:     nil,
			bPCapRunning: false,
			ch:           nil,
			packetWriter: nil,
			outDir:       func() string { rootPath, _ := os.Getwd(); return filepath.Join(rootPath, "lpcap") }(),
		}
	})
	return lpcap
}

func (lp *LPCap) GetPcapVersion() string {
	return pcap.Version()
}

func (lp *LPCap) GetDevsInfo() ([]storage.NetworkInterface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	nis := make([]storage.NetworkInterface, 0, len(devices))
	var ni storage.NetworkInterface
	for _, device := range devices {
		ni.Name = device.Name
		ni.Desc = device.Description
		for _, address := range device.Addresses {
			ni.IP = address.IP.String()
			ni.Netmask = address.Netmask.String()
			ni.BroadAddr = address.Broadaddr.String()
			ni.P2P = address.P2P.String()
		}
		nis = append(nis, ni)
	}

	return nis, nil
}

func (lp *LPCap) GetInterfaceInfo() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ss []string
	for _, iface := range ifaces {
		ss = append(ss, iface.Name)
	}
	return ss, err
}

func (lp *LPCap) StartPcap(conf storage.PcapConfig) error {
	if err := conf.Check(); err != nil {
		return err
	}
	if !utils.IsPathExist(lp.outDir) {
		utils.CreatDir(lp.outDir)
	}
	lp.ch = make(chan gopacket.Packet, 1000)
	if err := lp.output2PCapFile(lp.ch); err != nil {
		return err
	}
	lp.handle, err = pcap.OpenLive(conf.DeviceName, conf.SnapshotLen, conf.Promiscuous, conf.Timeout)
	if err != nil {
		log.Println(err)
		return err
	}
	if len(conf.BPF) > 0 {
		err = lp.handle.SetBPFFilter(conf.BPF)
		if err != nil {
			return err
		}
		log.Println("BPF filter:", conf.BPF)
	}
	log.Println("conf:", conf)
	lp.bPCapRunning = true
	packetSource := gopacket.NewPacketSource(lp.handle, lp.handle.LinkType())
	go func() {
		log.Println("流量捕获开始")
		for packet := range packetSource.Packets() {
			lp.ch <- packet
			global.ChPacketInfo <- lp.ParsePacket(packet)
		}
		lp.bPCapRunning = false
		close(lp.ch)
		log.Println("流量捕获结束")
	}()
	return err
}

func (lp *LPCap) IsPcapRunning() bool {
	return lp.bPCapRunning
}

func (lp *LPCap) StopPcap() {
	lp.handle.Close()
	lp.dumpFile.Close()
}

func (lp *LPCap) GetCurPcapPath() string {
	return lp.curPcapPath
}

func (lp *LPCap) output2PCapFile(c <-chan gopacket.Packet) error {
	lp.curPcapPath = lp.getCurPcapPath()
	lp.dumpFile, err = os.Create(lp.curPcapPath)
	if err != nil {
		return err
	}
	lp.packetWriter = pcapgo.NewWriter(lp.dumpFile)
	err = lp.packetWriter.WriteFileHeader(65535, layers.LinkTypeEthernet)
	if err != nil {
		return err
	}
	go func() {
		pcapSize := 24
		log.Println("output2PCapFile start")
		for packet := range c {
			err = lp.packetWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println(err)
				return
			}
			pcapSize += packet.Metadata().CaptureInfo.Length + 16
			fmt.Printf("\r%v packet count: %d length: %d", time.Now().Format("2006-01-02 15:04:05.000000"), 1, pcapSize)
		}
		log.Println("output2PCapFile exit")
	}()
	return err
}

func (lp *LPCap) getCurPcapPath() string {
	return filepath.Join(lp.outDir, time.Now().Format("2006-01-02-15-04-05.pcap"))
}

func (lp *LPCap) ParsePacket(packet gopacket.Packet) (pi storage.PacketInfo) {
	pi.Time = packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000")

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		pi.SrcMAC = ethernetPacket.SrcMAC.String()
		pi.DstMAC = ethernetPacket.DstMAC.String()
		pi.EthernetType = ethernetPacket.EthernetType.String()
	}

	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		pi.SrcIP = ip.SrcIP.String()
		pi.DstIP = ip.DstIP.String()
	}

	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)
		pi.SrcIP = ip.SrcIP.String()
		pi.DstIP = ip.DstIP.String()
		pi.Protocol = ip.Protocol.String()
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pi.SrcPort = tcp.SrcPort.String()
		pi.DstPort = tcp.DstPort.String()
	}

	tlsLayer := packet.Layer(layers.LayerTypeTLS)
	if tlsLayer != nil {
		tls, _ := tlsLayer.(*layers.TLS)
		pi.Protocol = tls.AppData[0].Version.String()
		log.Println(len(tls.AppData), len(tls.Handshake), len(tls.Alert))
	}

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		pi.Protocol = arp.Protocol.String()
	}

	pi.Len = packet.Metadata().Length
	pi.Data = packet.Data()

	//log.Println("All packet layers:")
	//for _, layer := range packet.Layers() {
	//	log.Println("- ", layer.LayerType())
	//}

	return
}

func (lp *LPCap) OpenOffline(filePath string) (pis []storage.PacketInfo, err error) {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		pis = append(pis, lp.ParsePacket(packet))
	}
	return
}
