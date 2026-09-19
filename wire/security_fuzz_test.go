package wire

import (
	"bytes"
	"testing"
)

func FuzzMsgTxBtcDecode(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		var tx MsgTx
		_ = tx.BtcDecode(bytes.NewReader(data), ProtocolVersion)
	})
}

func FuzzMsgBlockBtcDecode(f *testing.F) {
	f.Add(make([]byte, 80))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var block MsgBlock
		_ = block.BtcDecode(bytes.NewReader(data), ProtocolVersion)
	})
}
