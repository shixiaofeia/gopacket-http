package main

import (
	"context"
	"github.com/shixiaofeia/gopacket-http/packet"
	"log"
)

var eventCh = make(chan interface{}, 1024)

func main() {
	go handle()
	if err := packet.NewPacketHandle(context.Background(), "en0", eventCh).Listen(); err != nil {
		log.Println(err.Error())
	}
}

func handle() {
	for i := range eventCh {
		data := i.(packet.Event)
		log.Printf("request uri: %s, response status: %v", data.Req.RequestURI, data.Resp.Status)
	}
}
