package wire

import (
	"bytes"
	"testing"
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
