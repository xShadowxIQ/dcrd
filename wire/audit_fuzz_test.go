package wire

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

func FuzzAuditMsgTxDecode(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var tx MsgTx
		_ = tx.Deserialize(bytes.NewReader(data))

		var txWire MsgTx
		_ = txWire.BtcDecode(bytes.NewReader(data), ProtocolVersion)
	})
}

func FuzzAuditMsgBlockDecode(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var block MsgBlock
		_ = block.Deserialize(bytes.NewReader(data))

		var blockWire MsgBlock
		_ = blockWire.BtcDecode(bytes.NewReader(data), ProtocolVersion)
	})
}

func auditFramedMessage(command string, payload []byte) []byte {
	var header [MessageHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(MainNet))
	copy(header[4:4+CommandSize], command)
	binary.LittleEndian.PutUint32(header[4+CommandSize:8+CommandSize], uint32(len(payload)))
	checksum := chainhash.HashH(payload)
	copy(header[8+CommandSize:MessageHeaderSize], checksum[:4])
	return append(header[:], payload...)
}

func FuzzAuditReadMessageNTx(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _, _, _ = ReadMessageN(bytes.NewReader(auditFramedMessage(CmdTx, payload)),
			ProtocolVersion, MainNet)
	})
}

func FuzzAuditReadMessageNBlock(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _, _, _ = ReadMessageN(bytes.NewReader(auditFramedMessage(CmdBlock, payload)),
			ProtocolVersion, MainNet)
	})
}
