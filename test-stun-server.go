package main

import (
	"flag"
	stun "go-stun/stun"
	"log"
	"net"
	"os"
)

func main() {
	var (
		a = flag.String("addr", "0.0.0.0", "STUN server bind address")
		p = flag.Int("port", 19302, "STUN server listening port")
	)
	flag.Parse()

	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP(*a),
		Port: *p,
	}

	udpLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}

	buf := make([]byte, 10240)
	log.Printf("Starting TUN server at %s\n", udpAddr.String())

	for {
		size, srcAddr, err := udpLn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalln(err)
			break
		}

		go serve(udpLn, srcAddr, buf[:size], uint(size))
	}
}

func serve(udpLn *net.UDPConn, srcAddr *net.UDPAddr, buf []byte, size uint) {
	log.Printf("[client %s:%d] received %d bytes\n", srcAddr.IP.String(), srcAddr.Port, size)

	stunMsg := stun.STUNMessage{}
	stunMsg.Decode(buf, size)

	if stunMsg.Type == stun.MsgTypeBindingReq {
		log.Printf("[client %s:%d] received BindingRequest\n", srcAddr.IP.String(), srcAddr.Port)
		err := responseSTUNBindingSuccessResponse(udpLn, srcAddr, stunMsg)
		if err != nil {
			log.Fatalf("[client %s:%d] failed to respond BindingSuccessResponse: aborting", srcAddr.IP.String(), srcAddr.Port)
		}
	} else {
		log.Printf("[client %s:%d] unknown message type=%d\n", srcAddr.IP.String(), srcAddr.Port, stunMsg.Type)
	}
}

func responseSTUNBindingSuccessResponse(udpLn *net.UDPConn, srcAddr *net.UDPAddr, stunMsg stun.STUNMessage) error {
	respMsg := stun.STUNMessage{}
	respMsg.Init(stun.MsgTypeBindingSuccessResp)
	respMsg.TransactionIDLower64 = stunMsg.TransactionIDLower64
	respMsg.TransactionIDUpper32 = stunMsg.TransactionIDUpper32

	xorAttr := stun.STUNMessageAttr{}
	xorAttr.Type = stun.AttrTypeXorMappedAddress
	xorAttr.SetXorMappedAddressIPv4(stun.XorMappedAddressFamilyIPv4, srcAddr.IP, stunMsg.MagicCookie, uint16(srcAddr.Port), uint16(stunMsg.MagicCookie>>16))
	respMsg.AppendAttribute(xorAttr)

	respBuf, respSize := respMsg.Encode()
	log.Printf("[client %s:%d] responding BindingSuccessResponse size=%d", srcAddr.IP.String(), srcAddr.Port, respSize)
	udpLn.WriteToUDP(respBuf, srcAddr)

	return nil
}
