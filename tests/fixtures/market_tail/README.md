# Market response tail fixtures

These files contain historical Level2 market responses captured on 2026-09-05
for the 2026-09-04 trading session. They contain no login requests, login
responses, passwords, service tokens, or Passport64 credentials.

`boundaries.json` lists 16 raw TCP boundary samples: 15 Shanghai samples and
one Shenzhen sample, restricted to submitted orders (7175) and trades (7169).
Each `.market-wire` file contains one FDF market frame, its observed trailing
byte when present, and the beginning of the next FDF header. The manifest
records their SHA-256 digests, declared lengths/counts, actual tail bytes,
and next-header bytes. Tests replay these bytes through a local socket pair;
they never authenticate or connect to a market server.

`600519-trades-0930-0.market-frame` is the compressed frame body from a
09:30-09:35 trade query. It independently checks the trade-number-first row
layout and both endpoint records (2,947 rows, sequence numbers 172-3,118).

These bounded samples prove decoder and frame-boundary behavior, not complete
exchange coverage or retention for any other symbol, time range, or feed.
