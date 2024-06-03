package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"net"
	"time"
)

// Listen 监听网卡.
func (slf *Handle) Listen() error {
	// 获取网卡信息
	iface, err := net.InterfaceByName(slf.cardName)
	if err != nil {
		return fmt.Errorf("cardName %s not found, err: %v", slf.cardName, err)
	}
	log.Printf("cardName: %s, MTU: %d", slf.cardName, iface.MTU)

	// 打开设备监听
	handle, err := pcap.OpenLive(slf.cardName, 1024*1024, slf.promisc, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("openLive %s err: %v", slf.cardName, err)
	}
	defer handle.Close()

	// 设置过滤器
	if err := handle.SetBPFFilter(slf.bpf); err != nil {
		return fmt.Errorf("set bpf filter: %v", err)
	}

	go slf.EventHandle()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	streamFactory := NewHTTPStreamFactory(slf.eventCh)
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)

	ticker := time.Tick(time.Minute)
	var lastPacketTimestamp time.Time

	for {
		select {
		case <-slf.ctx.Done():
			return nil
		case packet := <-packetSource.Packets():
			netLayer := packet.NetworkLayer()
			if netLayer == nil {
				continue
			}
			transLayer := packet.TransportLayer()
			if transLayer == nil {
				continue
			}
			tcp, _ := transLayer.(*layers.TCP)
			if tcp == nil {
				continue
			}
			assembler.AssembleWithTimestamp(
				netLayer.NetworkFlow(),
				tcp,
				packet.Metadata().CaptureInfo.Timestamp)

			lastPacketTimestamp = packet.Metadata().CaptureInfo.Timestamp
		case <-ticker:
			assembler.FlushOlderThan(lastPacketTimestamp.Add(slf.flushTime))
		}
	}
}
