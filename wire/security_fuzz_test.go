package wire

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
)

func FuzzWire(f *testing.F) {
	f.Add(uint32(70000), uint32(MainNet), []byte{})
	f.Add(uint32(70001), uint32(MainNet), make([]byte, 32))
	f.Add(uint32(70000), uint32(TestNet3), make([]byte, 128))

	f.Fuzz(func(t *testing.T, pver uint32, net uint32, input []byte) {
		if len(input) >= MessageHeaderSize {
			length := binary.LittleEndian.Uint32(input[16:20])
			available := uint32(len(input) - MessageHeaderSize)
			if length > available {
				length = available
			}
			payload := input[MessageHeaderSize : MessageHeaderSize+int(length)]
			sum := chainhash.HashB(payload)
			copy(input[20:24], sum[:4])
		}

		r := bytes.NewReader(input)
		_, msg, _, err := ReadMessageN(r, pver, CurrencyNet(net))
		if err != nil || msg == nil {
			return
		}

		switch m := msg.(type) {
		case *MsgTx:
			_, _ = m.BytesPrefix()
			_, _ = m.BytesWitness()
			_ = m.PkScriptLocs()
		case *MsgBlock:
			_, _ = m.Bytes()
		}

		var out bytes.Buffer
		_, _ = WriteMessageN(&out, msg, pver, CurrencyNet(net))
	})
}
