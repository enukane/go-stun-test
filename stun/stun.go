package stun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
)

const (
	STUNMessageHeaderSize  uint   = 20
	STUNAttributesMinSize  uint   = 4
	STUNDefaultMagicCookie uint32 = 0x2112a442

	MsgTypeBindingReq         uint16 = 0x0001
	MsgTypeBindingResp        uint16 = 0x0002
	MsgTypeBindingSuccessResp uint16 = 0x0101

	AttrTypeXorMappedAddress   uint16 = 0x0020
	XorMappedAddressFamilyIPv4 uint8  = 0x01
	XorMappedAddressFamilyIPv6 uint8  = 0x02
)

type STUNMessageAttr struct {
	Type uint16
	Len  uint16
	Data []byte

	// XOR-MAPPED-ADDRESS
	XorMappedAddrFamily uint8
	XorMappedAddrPort   uint16
	XorMappedAddr       []byte
}

func (attr *STUNMessageAttr) Encode(buf []byte, limit uint) (uint, error) {
	size := uint(len(attr.Data))
	paddingLen := uint((4 - (size % 4)) % 4)
	if limit < size+paddingLen {
		return 0, fmt.Errorf("packet too small")
	}

	binary.BigEndian.PutUint16(buf[0:2], attr.Type)
	binary.BigEndian.PutUint16(buf[2:4], attr.Len)
	copy(buf[4:4+size], attr.Data[0:size])

	return uint(size + 4), nil
}

func (attr *STUNMessageAttr) Decode(buf []byte, size uint) (uint, error) {
	if size <= 0 {
		return 0, errors.New("Attribute buf size is invalid")
	}

	if size < STUNAttributesMinSize {
		return 0, errors.New("Attribute buffer has less than minimum size")
	}

	attr.Type = binary.BigEndian.Uint16(buf[0:2])
	attr.Len = binary.BigEndian.Uint16(buf[2:4])

	if uint(4+attr.Len) > size {
		return 0, fmt.Errorf("Attrubute buffer has insufficient buffer size (%d < %d)", 4+attr.Len, size)
	}

	attr.Data = buf[4 : 4+attr.Len]

	// type specific parsing
	switch attr.Type {
	case AttrTypeXorMappedAddress:
		attr.DecodeXorMappedAddress()
		break
	default:
	}

	return size, nil
}

func (attr *STUNMessageAttr) SetAttrData(buf []byte) {
	attr.Data = buf
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
func int2ip(num uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, num)
	return ip
}

func (attr *STUNMessageAttr) SetXorMappedAddressIPv4(family uint8, ipAddr net.IP, seedAddr uint32, port uint16, seedPort uint16) {
	attr.Len = 8
	attr.Data = make([]byte, 8)
	attr.XorMappedAddrFamily = XorMappedAddressFamilyIPv4
	u32Addr := ip2int(ipAddr)
	xoredAddr := (u32Addr ^ seedAddr)
	xoredPort := (port ^ seedPort)

	attr.Data[0] = 0x00 // reserved
	attr.Data[1] = attr.XorMappedAddrFamily
	binary.BigEndian.PutUint16(attr.Data[2:4], xoredPort)
	binary.BigEndian.PutUint32(attr.Data[4:8], xoredAddr)
}

func (attr *STUNMessageAttr) DecodeXorMappedAddress() {
	attr.XorMappedAddrFamily = attr.Data[1]
	attr.XorMappedAddrPort = uint16(attr.Data[2])<<8 + uint16(attr.Data[3])
	attr.XorMappedAddr = attr.Data[4:]
}

func (attr *STUNMessageAttr) CalculateXorMappedAddressPort(seed uint16) uint16 {
	return (attr.XorMappedAddrPort ^ seed)
}

func ConvertUint32OctetsToElm(addr_i uint32, octet int) uint8 {
	return uint8(addr_i & (0xff << (8 * octet)) >> (8 * octet))
}

func (attr *STUNMessageAttr) CalculateXorMappedAddressIPAddress(seed uint32) net.IP {
	addr_val := binary.BigEndian.Uint32(attr.XorMappedAddr) ^ seed
	ip := net.IPv4(
		ConvertUint32OctetsToElm(addr_val, 3),
		ConvertUint32OctetsToElm(addr_val, 2),
		ConvertUint32OctetsToElm(addr_val, 1),
		ConvertUint32OctetsToElm(addr_val, 0))

	return ip
}

type STUNMessage struct {
	Type                 uint16
	Len                  uint16
	MagicCookie          uint32
	TransactionIDUpper32 uint32
	TransactionIDLower64 uint64
	Attributes           []STUNMessageAttr

	// meta
}

func (msg *STUNMessage) Init(msgType uint16) {
	msg.Type = msgType
	msg.MagicCookie = STUNDefaultMagicCookie
	msg.TransactionIDUpper32 = rand.Uint32()
	msg.TransactionIDLower64 = rand.Uint64()
	msg.Attributes = []STUNMessageAttr{}
}

func (msg *STUNMessage) AppendAttribute(attr STUNMessageAttr) {
	msg.Attributes = append(msg.Attributes, attr)
}

func (msg *STUNMessage) Encode() ([]byte, uint) {
	buf := make([]byte, 2048)
	msg.Len = 0
	if len(msg.Attributes) > 0 {
		/* append attrs starting from 20, calculate msg.Len */
		/* start fron idx:20 */
		idx := uint(20)
		for _, attr := range msg.Attributes {
			size, err := attr.Encode(buf[idx:], 2048-idx)
			if err != nil {
				break
			}

			if size%4 != 0 {
				log.Printf("Attribute is not aligned to 4 bytes")
				break
			}
			msg.Len += uint16(size)
			idx += size
		}
	}

	binary.BigEndian.PutUint16(buf[0:2], msg.Type)
	binary.BigEndian.PutUint16(buf[2:4], msg.Len)
	binary.BigEndian.PutUint32(buf[4:8], msg.MagicCookie)
	binary.BigEndian.PutUint64(buf[8:16], msg.TransactionIDLower64)
	binary.BigEndian.PutUint32(buf[16:20], msg.TransactionIDUpper32)

	bufSize := uint(msg.Len) + STUNMessageHeaderSize

	return buf[:bufSize], bufSize
}

func (msg *STUNMessage) Decode(buf []byte, size uint) {
	msg.Type = binary.BigEndian.Uint16(buf[0:2])
	msg.Len = binary.BigEndian.Uint16(buf[2:4])
	msg.MagicCookie = binary.BigEndian.Uint32(buf[4:8])
	msg.TransactionIDLower64 = binary.BigEndian.Uint64(buf[8:16])
	msg.TransactionIDUpper32 = binary.BigEndian.Uint32(buf[16:20])

	idx := uint(20)
	for {
		if idx >= size {
			break
		}
		attr := STUNMessageAttr{}
		forwarded, err := attr.Decode(buf[idx:size], size-idx)
		if err != nil {
			break
		}

		msg.Attributes = append(msg.Attributes, attr)

		if attr.Type == AttrTypeXorMappedAddress {
			attr.DecodeXorMappedAddress()
			addr := attr.CalculateXorMappedAddressIPAddress(msg.MagicCookie)
			port := attr.CalculateXorMappedAddressPort(uint16(msg.MagicCookie >> 16))
			log.Printf("Xor-Mapped-Address is %v:%d\n", addr, port)
		}

		idx += forwarded
	}
}
