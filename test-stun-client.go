package main

import (
	"flag"
	"fmt"
	stun "go-stun/stun"
	"log"
	"net"
	"os"
)

func GenerateSTUNBindingRequest() ([]byte, uint) {
	msg := stun.STUNMessage{}
	msg.Init(stun.MsgTypeBindingReq)
	return msg.Encode()
}

func SendSTUNMessage(msgBuf []byte, size uint, destAddrPort string) []byte {
	conn, err := net.Dial("udp", destAddrPort)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}

	defer conn.Close()

	log.Printf("sending STUN message size=%d\n", size)
	//for i := 0; i < int(size); i++ {
	//	fmt.Printf("0x%02x ", msgBuf[i])
	//}
	//fmt.Printf("\n")
	sentSize, err := conn.Write(msgBuf[:size])
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}

	if sentSize != int(size) {
		log.Fatalln("error in sending data: size=%u but sent only %u bytes\n", size, sentSize)
	} else {
		log.Printf("sent %d bytes to server\n", sentSize)
	}

	recvBuf := make([]byte, 10240)

	readSize, err := conn.Read(recvBuf)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	log.Printf("received %d bytes from server", readSize)

	return recvBuf[:readSize]
}

func main() {
	var (
		a = flag.String("addr", "172.217.213.127", "STUN server address")
		p = flag.Int("port", 19302, "STUN server port")
	)
	flag.Parse()

	serverAddrPort := fmt.Sprintf("%s:%d", *a, *p)
	log.Printf("sending BindingRequest to %s\n", serverAddrPort)

	data, size := GenerateSTUNBindingRequest()
	// stun.l.google.com 172.217.213.127
	//recvBuf := SendSTUNMessage(data, size, "172.217.213.127:19302")
	//recvBuf := SendSTUNMessage(data, size, "172.217.219.127:19302")
	//recvBuf := SendSTUNMessage(data, size, "127.0.0.1:19302")
	recvBuf := SendSTUNMessage(data, size, serverAddrPort)

	log.Printf("decoding received data")
	msg := stun.STUNMessage{}
	msg.Decode(recvBuf, uint(len(recvBuf)))
}
