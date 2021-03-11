package main

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Custom method
type AWSGeneve struct {
	layers.Geneve
}

// Geneve Header:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Virtual Network Identifier (VNI)       |    Reserved   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Variable Length Options                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Geneve Tunnel Options
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Option Class         |      Type     |R|R|R| Length  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Variable Option Data                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (a *AWSGeneve) computeOptionsLength() uint8 {
	sz := 0
	for _, opt := range a.Options {
		sz += len(opt.Data)
	}
	return uint8(sz)
}

func b2i(b bool) int8 {
	if b {
		return 1
	}
	return 0
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (a *AWSGeneve) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// prepend 8 bytes for the static sized portion of the header
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}

	// Version(2 bits) + Opt Len(6 bits) in byte 0
	bytes[0] = byte((a.Version << 6) | a.computeOptionsLength())

	// OAM bit, Critical bit + Reserved(6 empty bits) in byte 1
	bytes[1] = byte(b2i(a.OAMPacket) << 7 | b2i(a.CriticalOption) << 6)

	// Protocol type
	binary.BigEndian.PutUint16(bytes[2:3], uint16(a.Protocol))

	// VNI(24 bits) + Reserved(8 empty bits)
	binary.BigEndian.PutUint32(bytes[4:6], a.VNI)

	// Options now...

	return nil
}