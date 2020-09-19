package main

import (
	"fmt"
	stun "go-stun/stun"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/panjf2000/gnet"
)

type echoServer struct {
	*gnet.EventServer
}

func (es *echoServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	out = frame
	return
}

type STUNServer struct {
	*gnet.EventServer
}

func GenerateSTUNBindingSuccessResponse(stunMsg *stun.STUNMessage, remoteAddr net.Addr) ([]byte, error) {
	respMsg := stun.STUNMessage{}
	respMsg.Init(stun.MsgTypeBindingSuccessResp)
	respMsg.TransactionIDLower64 = stunMsg.TransactionIDLower64
	respMsg.TransactionIDUpper32 = stunMsg.TransactionIDUpper32

	remoteInfos := strings.Split(remoteAddr.String(), ":")
	if len(remoteInfos) != 2 {
		return nil, fmt.Errorf("Failed to acquire proper remote address '%s'", remoteAddr.String())
	}
	remotePortInt, _ := strconv.Atoi(remoteInfos[1])

	xorAttr := stun.STUNMessageAttr{}
	xorAttr.Type = stun.AttrTypeXorMappedAddress
	xorAttr.SetXorMappedAddressIPv4(stun.XorMappedAddressFamilyIPv4, net.ParseIP(remoteInfos[0]), stunMsg.MagicCookie, uint16(remotePortInt), uint16(stunMsg.MagicCookie>>16))
	respMsg.AppendAttribute(xorAttr)

	respBuf, respSize := respMsg.Encode()
	log.Printf("[client %s] responding BindingSuccessResponse size=%d", remoteAddr)
	if respSize <= 0 {
		return nil, fmt.Errorf("Failed to encode message")
	}

	return respBuf, nil

}

func (stunSrv *STUNServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	remoteAddr := c.RemoteAddr()
	localAddr := c.LocalAddr()

	log.Printf("received %d bytes to %s from %s (out len %d cap %d)\n", len(frame), localAddr, remoteAddr, len(out), cap(out))

	stunMsg := stun.STUNMessage{}
	stunMsg.Decode(frame, uint(len(frame)))

	if stunMsg.Type == stun.MsgTypeBindingReq {
		log.Printf("[client %s] received BindingRequest\n", remoteAddr)
		buf, err := GenerateSTUNBindingSuccessResponse(&stunMsg, remoteAddr)
		if err != nil {
			log.Fatalf("[client %s] failed to respond BindingSuccessResponse: aborting", remoteAddr)
		}
		return buf, gnet.None
	} else {
		log.Printf("[client %s] unknown message type=%d\n", remoteAddr, stunMsg.Type)
	}

	return []byte{}, gnet.None
}

func main() {
	stunServer := new(STUNServer)
	gnet.Serve(stunServer, "udp://:19302", gnet.WithMulticore(true))
}
