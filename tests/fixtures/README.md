# Real-world artifact fixtures

Real Windows forensic artifacts used to validate the parsers against actual
tool output (not just hand-built synthetic bytes in unit tests).

Source: [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/`
(Apache License 2.0). Pulled in as-is for parser correctness testing.

- `prefetch/` — 8 real `.pf` files, mix of uncompressed SCCA (Win7) and
  `MAM\x04`-wrapped LZXPRESS-Huffman-compressed (Win10/11)
- `evtx/` — `System.evtx`, `System2.evtx`
- `lnk/` — `NeroInfoTool.lnk`, `example.lnk`, `unpaired_surrogate.lnk`
  (the last one exercises unpaired UTF-16 surrogate handling)
- `mft/MFT` — a real `$MFT` extract, used to validate MACB timeline
  extraction and `$SI`/`$FN` timestomp detection against a live filesystem
