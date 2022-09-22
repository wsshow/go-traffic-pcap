package global

import "go-traffic-pcap/storage"

var ChPacketInfo = make(chan storage.PacketInfo, 1000)
